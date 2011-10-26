/*
 * Hash Table Data Type
 * Copyright (C) 1997 Kaz Kylheku <kaz@ashi.footprints.net>
 *
 * Free Software License:
 *
 * All rights are reserved by the author, with the following exceptions:
 * Permission is granted to freely reproduce and distribute this software,
 * possibly in exchange for a fee, provided that this copyright notice appears
 * intact. Permission is also granted to adapt this software to produce
 * derivative works, as long as the modified versions carry this copyright
 * notice and additional notices stating that the work has been modified.
 * The copyright extends to translations of this work into other languages,
 * including machine languages. 
 *
 * $Id: hash.c,v 1.1 2005-01-07 01:32:37 damion Exp $
 * $Name:  $
 */

#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#define HASH_IMPLEMENTATION
#include "hash.h"

static const char rcsid[] = "$Id: hash.c,v 1.1 2005-01-07 01:32:37 damion Exp $";
static const char right[] = "Copyright (C) 1997 Kaz Kylheku";

#define INIT_BITS	6
#define INIT_SIZE	(1UL << (INIT_BITS))	/* must be power of two		*/
#define INIT_MASK	((INIT_SIZE) - 1)

static hnode_t *hnode_alloc(void *context);
static void hnode_free(hnode_t *node, void *context);
static hash_val_t hash_fun_default(const void *key);
static int hash_comp_default(const void *key1, const void *key2);

int hash_val_t_bit;

/*
 * Compute the number of bits in the hash_val_t type.  We know that hash_val_t
 * is an unsigned integral type. Thus the highest value it can hold is a
 * Mersenne number (power of two, less one). We initialize a hash_val_t
 * object with this value and then shift bits out one by one while counting.
 * Notes:
 * 1. HASH_VAL_T_MAX is a Mersenne number---one that is one less than a power
 *    of two. This means that its binary representation consists of all one
 *    bits, and hence ``val'' is initialized to all one bits.
 * 2. We reset the bit count to zero in case this function is invoked more than
 *    once.
 * 3. While bits remain in val, we increment the bit count and shift it to the
 *    right, replacing the topmost bit by zero.
 */

static void compute_bits(void)
{
    hash_val_t val = HASH_VAL_T_MAX;	/* 1 */
    int bits = 0;

    while (val) {	/* 3 */
	bits++;
	val >>= 1;
    }

    hash_val_t_bit = bits;
}

/*
 * Verify whether the given argument is a power of two.
 */

static int is_power_of_two(hash_val_t arg)
{
    if (arg == 0)
	return 0;
    while ((arg & 1) == 0)
	arg >>= 1;
    return (arg == 1);
}

/*
 * Compute a shift amount from a given table size 
 */

static hash_val_t compute_mask(hashcount_t size)
{
    hash_val_t mask = size;
    assert (is_power_of_two(size));
    assert (size >= 2);

    mask /= 2;

    while ((mask & 1) == 0)
	mask |= (mask >> 1);

    return mask;
}

/*
 * Initialize the table of pointers to null.
 */

static void clear_table(hash_t *hash)
{
    hash_val_t i;

    for (i = 0; i < hash->nchains; i++)
	hash->table[i] = NULL;
}

/*
 * Double the size of a dynamic table. This works as follows. Each chain splits
 * into two adjacent chains.  The shift amount increases by one, exposing an
 * additional bit of each hashed key. For each node in the original chain, the
 * value of this newly exposed bit will decide which of the two new chains will
 * receive the node: if the bit is 1, the chain with the higher index will have
 * the node, otherwise the lower chain will receive the node. In this manner,
 * the hash table will continue to function exactly as before without having to
 * rehash any of the keys.
 * Notes:
 * 1.  Overflow check.
 * 2.  The new number of chains is twice the old number of chains.
 * 3.  The new mask is one bit wider than the previous, revealing a
 *     new bit in all hashed keys.
 * 4.  Allocate a new table of chain pointers that is twice as large as the
 *     previous one.
 * 5.  If the reallocation was successful, we perform the rest of the growth
 *     algorithm, otherwise we do nothing.
 * 6.  The exposed_bit variable holds a mask with which each hashed key can be
 *     AND-ed to test the value of its newly exposed bit.
 * 7.  Loop over the lower half of the table, which, at first, holds all of
 *     the chains.
 * 8.  Each chain from the original table must be split into two chains.
 *     The nodes of each chain are examined in turn. The ones whose key value's
 *     newly exposed bit is 1 are removed from the chain and put into newchain
 *     (Steps 9 through 14). After this separation, the new chain is assigned
 *     into its appropriate place in the upper half of the table (Step 15).
 * 9.  Since we have relocated the table of pointers, we have to fix the
 *     back-reference from the first node of each non-empty chain so it
 *     properly refers to the moved pointer.
 * 10. We loop over the even chain looking for any nodes whose exposed bit is
 *     set. Such nodes are removed from the lower-half chain and put into its
 *     upper-half sister.
 * 11. Before moving the node to the other chain, we remember what the next
 *     node is so we can coninue the loop. We have to do this because we will
 *     be overwriting the node's next pointer when we insert it to its new
 *     home.
 * 12. The next node's back pointer must be updated to skip to the previous
 *     node.
 * 13. The deleted node's back pointer must be updated to refer to the next
 *     node.
 * 14. We insert the node at the beginning of the new chain.
 * 15. Place the new chain into an upper-half slot.
 * 16. We have finished dealing with the chains and nodes. We now update
 *     the various bookeeping fields of the hash structure.
 */

static void grow_table(hash_t *hash)
{
    hnode_t **newtable;

    assert (2 * hash->nchains > hash->nchains);	/* 1 */

    newtable = realloc(hash->table,
	    sizeof *newtable * hash->nchains * 2);	/* 4 */

    if (newtable) {	/* 5 */
	hash_val_t mask = (hash->mask << 1) | 1;	/* 3 */
	hash_val_t exposed_bit = mask ^ hash->mask;	/* 6 */
	hash_val_t chain;

	assert (mask != hash->mask);

	for (chain = 0; chain < hash->nchains; chain++) {	/* 7 */
	    hnode_t *hptr = newtable[chain];	/* 8 */
	    hnode_t *newchain = NULL;
	    if (hptr)	/* 9 */
		hptr->pself = &newtable[chain];
	    while (hptr) {	/* 10 */
		if ((hptr->hkey & exposed_bit)) {
		    hnode_t *next = hptr->next;		/* 11 */
		    if (next)				/* 12 */
			next->pself = hptr->pself;
		    *hptr->pself = next;		/* 13 */
		    hptr->next = newchain;		/* 14 */
		    if (newchain)
		    	newchain->pself = &hptr->next;
		    newchain = hptr;
		    hptr->pself = &newchain;
		    hptr = next;
		} else {
		    hptr = hptr->next;
		}
	    }
	    newtable[chain + hash->nchains] = newchain;	/* 15 */
	    if (newchain)
		newchain->pself = &newtable[chain + hash->nchains];
	}
	hash->table = newtable;		/* 16 */
	hash->mask = mask;
	hash->nchains *= 2;
	hash->lowmark *= 2;
	hash->highmark *= 2;
    }
    assert (hash_verify(hash));
}

/*
 * Cut a table size in half. This is done by folding together adjacent chains
 * and populating the lower half of the table with these chains. The chains are
 * simply spliced together. Once this is done, the whole table is reallocated
 * to a smaller object.
 * Notes:
 * 1.  It is illegal to have a hash table with one slot. This would mean that
 *     hash->shift is equal to hash_val_t_bit, an illegal shift value.
 *     Also, other things could go wrong, such as hash->lowmark becoming zero.
 * 2.  Looping over each adjacent chain of pairs, the lo_chain is set to
 *     reference the lower-numbered member of the pair, whereas hi_chain
 *     is the index of the higher-numbered one.
 * 3.  The intent here is to compute a pointer to the last node of the
 *     lower chain into the lo_tail variable. If this chain is empty,
 *     lo_tail ends up with a null value.
 * 4.  If the lower chain is not empty, we have to merge chains, but only
 *     if the upper chain is also not empty. In either case, the lower chain
 *     will come first, with the upper one appended to it.
 * 5.  The first part of the join is done by having the tail node of the lower
 *     chain point to the head node of the upper chain. If the upper chain
 *     is empty, this is remains a null pointer.
 * 6.  If the upper chain is non-empty, we must do the additional house-keeping
 *     task of ensuring that the upper chain's first node's back-pointer
 *     references the tail node of the lower chain properly.
 * 8.  If the low chain is empty, but the high chain is not, then the
 *     high chain simply becomes the new chain.
 * 9.  Otherwise if both chains are empty, then the merged chain is also empty.
 * 10. All the chain pointers are in the lower half of the table now, so
 *     we reallocate it to a smaller object. This, of course, invalidates
 *     all pointer-to-pointers which reference into the table from the
 *     first node of each chain.
 * 11. Though it's unlikely, the reallocation may fail. In this case we
 *     pretend that the table _was_ reallocated to a smaller object.
 * 12. This loop performs the housekeeping task of updating the back pointers
 *     from the first node of each chain so that they reference their 
 *     corresponding table entries.
 * 13. Finally, update the various table parameters to reflect the new size.
 */

static void shrink_table(hash_t *hash)
{
    hash_val_t chain, nchains;
    hnode_t **newtable, *lo_tail, *lo_chain, *hi_chain;

    assert (hash->nchains >= 2);			/* 1 */
    nchains = hash->nchains / 2;

    for (chain = 0; chain < nchains; chain++) {
	lo_chain = hash->table[chain];		/* 2 */
	hi_chain = hash->table[chain + nchains];
	for (lo_tail=lo_chain; lo_tail && lo_tail->next; lo_tail=lo_tail->next)
	    ;	/* 3 */
	if (lo_chain) {					/* 4 */
	    lo_tail->next = hi_chain;			/* 5 */
	    if (hi_chain)				/* 6 */
		hi_chain->pself = &lo_tail->next;
	} else if (hi_chain) {				/* 8 */
	    hash->table[chain] = hi_chain;
	} else {
	    hash->table[chain] = NULL;			/* 9 */
	}
    }
    newtable = realloc(hash->table,
	    sizeof *newtable * nchains);		/* 10 */
    if (newtable)					/* 11 */
	hash->table = newtable;
    for (chain = 0; chain < nchains; chain++)		/* 12 */
	if (hash->table[chain])
	    hash->table[chain]->pself = &hash->table[chain];
    hash->mask >>= 1;			/* 13 */
    hash->nchains = nchains;
    hash->lowmark /= 2;
    hash->highmark /= 2;
    assert (hash_verify(hash));
}


/*
 * Create a dynamic hash table. Both the hash table structure and the table
 * itself are dynamically allocated. Furthermore, the table is extendible in
 * that it will automatically grow as its load factor increases beyond a
 * certain threshold.
 * Notes:
 * 1. If the number of bits in the hash_val_t type has not been computed yet,
 *    we do so here, because this is likely to be the first function that the
 *    user calls.
 * 2. Safe malloc is used for added checking. The checking is disabled by
 *    defining NDEBUG, which turns the safe malloc routines (via the
 *    preprocessor) into direct calls to malloc, free, etc.
 * 3. If a hash table control structure is successfully allocated, we
 *    proceed to initialize it. Otherwise we return a null pointer.
 * 4. Using the safe allocator, we try to allocate the table of hash
 *    chains.
 * 5. If we were able to allocate the hash chain table, we can finish
 *    initializing the hash structure and the table. Otherwise, we must
 *    backtrack by freeing the hash structure.
 * 6. INIT_SIZE should be a power of two. The high and low marks are always set
 *    to be twice the table size and half the table size respectively. When the
 *    number of nodes in the table grows beyond the high size (beyond load
 *    factor 2), it will double in size to cut the load factor down to about
 *    about 1. If the table shrinks down to or beneath load factor 0.5,
 *    it will shrink, bringing the load up to about 1. However, the table
 *    will never shrink beneath INIT_SIZE even if it's emptied.
 * 7. This indicates that the table is dynamically allocated and dynamically
 *    resized on the fly. A table that has this value set to zero is
 *    assumed to be statically allocated and will not be resized.
 * 8. The table of chains must be properly reset to all null pointers.
 */

hash_t *hash_create(hashcount_t maxcount, hash_comp_t compfun,
	hash_fun_t hashfun)
{
    hash_t *hash;

    if (hash_val_t_bit == 0)	/* 1 */
	compute_bits();

    hash = malloc(sizeof *hash);	/* 2 */

    if (hash) {		/* 3 */
	hash->table = malloc(sizeof *hash->table * INIT_SIZE);	/* 4 */
	if (hash->table) {	/* 5 */
	    hash->nchains = INIT_SIZE;		/* 6 */
	    hash->highmark = INIT_SIZE * 2;
	    hash->lowmark = INIT_SIZE / 2;
	    hash->count = 0;
	    hash->maxcount = maxcount;
	    hash->compare = compfun ? compfun : hash_comp_default;
	    hash->hash = hashfun ? hashfun : hash_fun_default;
	    hash->allocnode = hnode_alloc;
	    hash->freenode = hnode_free;
	    hash->context = NULL;
	    hash->mask = INIT_MASK;
	    hash->dynamic = 1;			/* 7 */
	    clear_table(hash);			/* 8 */
	    assert (hash_verify(hash));
	    return hash;
	} 
	free(hash);
    }

    return NULL;
}

/*
 * Select a different set of node allocator routines.
 */

void hash_set_allocator(hash_t *hash, hnode_alloc_t al,
	hnode_free_t fr, void *context)
{
    assert (hash_count(hash) == 0);
    assert ((al == 0 && fr == 0) || (al != 0 && fr != 0));

    hash->allocnode = al ? al : hnode_alloc;
    hash->freenode = fr ? fr : hnode_free;
    hash->context = context;
}

void hash_free(hash_t *hash)
{
    hscan_t hs;
    hnode_t *node;
    hash_scan_begin(&hs, hash);
    while ((node = hash_scan_next(&hs))) {
	hash_scan_delete(hash, node);
	hash->freenode(node, hash->context);
    }
    hash_destroy(hash);
}

/*
 * Free a dynamic hash table structure.
 */

void hash_destroy(hash_t *hash)
{
    assert (hash_val_t_bit != 0);
    assert (hash_isempty(hash));
    free(hash->table);
    free(hash);
}

/*
 * Initialize a user supplied hash structure. The user also supplies a table of
 * chains which is assigned to the hash structure. The table is static---it
 * will not grow or shrink.
 * 1. See note 1. in hash_create().
 * 2. The user supplied array of pointers hopefully contains nchains nodes.
 * 3. See note 7. in hash_create().
 * 4. We must dynamically compute the mask from the given power of two table
 *    size. 
 * 5. The user supplied table can't be assumed to contain null pointers,
 *    so we reset it here.
 */

hash_t *hash_init(hash_t *hash, hashcount_t maxcount,
	hash_comp_t compfun, hash_fun_t hashfun, hnode_t **table,
	hashcount_t nchains)
{
    if (hash_val_t_bit == 0)	/* 1 */
	compute_bits();

    assert (is_power_of_two(nchains));

    hash->table = table;	/* 2 */
    hash->nchains = nchains;
    hash->count = 0;
    hash->maxcount = maxcount;
    hash->compare = compfun ? compfun : hash_comp_default;
    hash->hash = hashfun ? hashfun : hash_fun_default;
    hash->dynamic = 0;		/* 3 */
    hash->mask = compute_mask(nchains);	/* 4 */
    clear_table(hash);		/* 5 */

    assert (hash_verify(hash));

    return hash;
}

/*
 * Reset the hash scanner so that the next element retrieved by
 * hash_scan_next() shall be the first element on the first non-empty chain. 
 * Notes:
 * 1. Locate the first non empty chain.
 * 2. If an empty chain is found, remember which one it is and set the next
 *    pointer to refer to its first element.
 * 3. Otherwise if a chain is not found, set the next pointer to NULL
 *    so that hash_scan_next() shall indicate failure.
 */

void hash_scan_begin(hscan_t *scan, hash_t *hash)
{
    hash_val_t nchains = hash->nchains;
    hash_val_t chain;

    scan->hash = hash;

    /* 1 */

    for (chain = 0; chain < nchains && hash->table[chain] == 0; chain++)
	;

    if (chain < nchains) {	/* 2 */
	scan->chain = chain;
	scan->next = hash->table[chain];
    } else {			/* 3 */
	scan->next = NULL;
    }
}

/*
 * Retrieve the next node from the hash table, and update the pointer
 * for the next invocation of hash_scan_next(). 
 * Notes:
 * 1. Remember the next pointer in a temporary value so that it can be
 *    returned.
 * 2. This assertion essentially checks whether the module has been properly
 *    initialized. The first point of interaction with the module should be
 *    either hash_create() or hash_init(), both of which set hash_val_t_bit to
 *    a non zero value.
 * 3. If the next pointer we are returning is not NULL, then the user is
 *    allowed to call hash_scan_next() again. We prepare the new next pointer
 *    for that call right now. That way the user is allowed to delete the node
 *    we are about to return, since we will no longer be needing it to locate
 *    the next node.
 * 4. If there is a next node in the chain (next->next), then that becomes the
 *    new next node, otherwise ...
 * 5. We have exhausted the current chain, and must locate the next subsequent
 *    non-empty chain in the table.
 * 6. If a non-empty chain is found, the first element of that chain becomes
 *    the new next node. Otherwise there is no new next node and we set the
 *    pointer to NULL so that the next time hash_scan_next() is called, a null
 *    pointer shall be immediately returned.
 */


hnode_t *hash_scan_next(hscan_t *scan)
{
    hnode_t *next = scan->next;		/* 1 */
    hash_t *hash = scan->hash;
    hash_val_t chain = scan->chain + 1;
    hash_val_t nchains = hash->nchains;

    assert (hash_val_t_bit != 0);	/* 2 */

    if (next) {			/* 3 */
	if (next->next) {	/* 4 */
	    scan->next = next->next;
	} else {
	    while (chain < nchains && hash->table[chain] == 0)	/* 5 */
	    	chain++;
	    if (chain < nchains) {	/* 6 */
		scan->chain = chain;
		scan->next = hash->table[chain];
	    } else {
		scan->next = NULL;
	    }
	}
    }
    return next;
}

/*
 * Insert a node into the hash table.
 * Notes:
 * 1. It's illegal to insert more than the maximum number of nodes. The client
 *    should verify that the hash table is not full before attempting an
 *    insertion.
 * 2. The same key may not be inserted into a table twice.
 * 3. If the table is dynamic and the load factor is already at >= 2,
 *    grow the table.
 * 4. We take the top N bits of the hash value to derive the chain index,
 *    where N is the base 2 logarithm of the size of the hash table. 
 */

void hash_insert(hash_t *hash, hnode_t *node, void *key)
{
    hash_val_t hkey, chain;

    assert (hash_val_t_bit != 0);
    assert (hash->count < hash->maxcount);	/* 1 */
    assert (hash_lookup(hash, key) == NULL);	/* 2 */

    if (hash->dynamic && hash->count >= hash->highmark)	/* 3 */
	grow_table(hash);

    hkey = hash->hash(key);
    chain = hkey & hash->mask;	/* 4 */

    node->key = key;
    node->hkey = hkey;
    node->pself = hash->table + chain;
    node->next = hash->table[chain];
    if (node->next)
	node->next->pself = &node->next;
    hash->table[chain] = node;
    hash->count++;

    assert (hash_verify(hash));
}

/*
 * Find a node in the hash table and return a pointer to it.
 * Notes:
 * 1. We hash the key and keep the entire hash value. As an optimization, when
 *    we descend down the chain, we can compare hash values first and only if
 *    hash values match do we perform a full key comparison. 
 * 2. To locate the chain from among 2^N chains, we look at the lower N bits of
 *    the hash value by anding them with the current mask.
 * 3. Looping through the chain, we compare the stored hash value inside each
 *    node against our computed hash. If they match, then we do a full
 *    comparison between the unhashed keys. If these match, we have located the
 *    entry.
 */

hnode_t *hash_lookup(hash_t *hash, void *key)
{
    hash_val_t hkey, chain;
    hnode_t *nptr;

    hkey = hash->hash(key);		/* 1 */
    chain = hkey & hash->mask;		/* 2 */

    for (nptr = hash->table[chain]; nptr; nptr = nptr->next) {	/* 3 */
	if (nptr->hkey == hkey && hash->compare(nptr->key, key) == 0)
	    return nptr;
    }

    return NULL;
}

/*
 * Delete the given node from the hash table. This is easy, because each node
 * contains a back pointer to the previous node's next pointer.
 * Notes:
 * 1. The node must belong to this hash table, and its key must not have
 *    been tampered with.
 * 2. If there is a next node, then we must update its back pointer to
 *    skip this node.
 * 3. We must update the pointer that is pointed at by the back-pointer
 *    to skip over the node that is being deleted and instead point to
 *    the successor (or to NULL if the node being deleted is the last one).
 */

hnode_t *hash_delete(hash_t *hash, hnode_t *node)
{
    assert (hash_lookup(hash, node->key) == node);	/* 1 */
    assert (hash_val_t_bit != 0);

    if (hash->dynamic && hash->count <= hash->lowmark
	    && hash->count > INIT_SIZE)
	shrink_table(hash);

    if (node->next)	/* 2 */
	node->next->pself = node->pself;
    *node->pself = node->next;	/* 3 */
    hash->count--;
    assert (hash_verify(hash));
    return node;
}

int hash_alloc_insert(hash_t *hash, void *key, void *data)
{
    hnode_t *node = hash->allocnode(hash->context);

    if (node) {
	hnode_init(node, data);
	hash_insert(hash, node, key);
	return 1;
    }
    return 0;
}

void hash_delete_free(hash_t *hash, hnode_t *node)
{
    hash_delete(hash, node);
    hash->freenode(node, hash->context);
}

/*
 *  Exactly like hash_delete, except does not trigger table shrinkage. This is to be
 *  used from within a hash table scan operation. See notes for hash_delete.
 */

hnode_t *hash_scan_delete(hash_t *hash, hnode_t *node)
{
    assert (hash_lookup(hash, node->key) == node);	/* 1 */
    assert (hash_val_t_bit != 0);

    if (node->next)	/* 2 */
	node->next->pself = node->pself;
    *node->pself = node->next;	/* 3 */
    hash->count--;
    assert (hash_verify(hash));
    return node;
}

/*
 * Verify whether the given object is a valid hash table. This means
 * Notes:
 * 1. If the hash table is dynamic, verify whether the high and
 *    low expansion/shrinkage thresholds are powers of two.
 * 2. For each chain, verify whether the back pointers are correctly
 *    set. Count all nodes in the table, and test each hash value
 *    to see whether it is correct for the node's chain.
 */

int hash_verify(hash_t *hash)
{
    hashcount_t count = 0;
    hash_val_t chain;
    hnode_t **npp;

    if (hash->dynamic) {	/* 1 */
	if (hash->lowmark >= hash->highmark)
	    return 0;
	if (!is_power_of_two(hash->highmark))
	    return 0;
	if (!is_power_of_two(hash->lowmark))
	    return 0;
    }

    for (chain = 0; chain < hash->nchains; chain++) {	/* 2 */
	for (npp = hash->table + chain; *npp; npp = &(*npp)->next) {
	    if ((*npp)->pself != npp)
		return 0;
	    if (((*npp)->hkey & hash->mask) != chain)
		return 0;
	    count++;
	}
    }

    if (count != hash->count)
	return 0;

    return 1;
}

/*
 * Test whether the hash table is full and return 1 if this is true,
 * 0 if it is false.
 */

#undef hash_isfull
int hash_isfull(hash_t *hash)
{
    return hash->count == hash->maxcount;
}

/*
 * Test whether the hash table is empty and return 1 if this is true,
 * 0 if it is false.
 */

#undef hash_isempty
int hash_isempty(hash_t *hash)
{
    return hash->count == 0;
}

static hnode_t *hnode_alloc(void *context)
{
    return malloc(sizeof *hnode_alloc(NULL));
}

static void hnode_free(hnode_t *node, void *context)
{
    free(node);
}


/*
 * Create a hash table node dynamically and assign it the given data.
 */

hnode_t *hnode_create(void *data)
{
    hnode_t *node = malloc(sizeof *node);
    if (node) {
	node->data = data;
	node->next = NULL;
	node->pself = NULL;
    }
    return node;
}

/*
 * Initialize a client-supplied node 
 */

hnode_t *hnode_init(hnode_t *hnode, void *data)
{
    hnode->data = data;
    hnode->next = NULL;
    hnode->pself = NULL;
    return hnode;
}

/*
 * Destroy a dynamically allocated node.
 */

void hnode_destroy(hnode_t *hnode)
{
    free(hnode);
}

#undef hnode_put
void hnode_put(hnode_t *node, void *data)
{
    node->data = data;
}

#undef hnode_get
void *hnode_get(hnode_t *node)
{
    return node->data;
}

#undef hnode_getkey
void *hnode_getkey(hnode_t *node)
{
    return node->key;
}

#undef hash_count
hashcount_t hash_count(hash_t *hash)
{
    return hash->count;
}

#undef hash_size
hashcount_t hash_size(hash_t *hash)
{
    return hash->nchains;
}

static hash_val_t hash_fun_default(const void *key)
{
    static unsigned long randbox[] = {
	0x49848f1bU, 0xe6255dbaU, 0x36da5bdcU, 0x47bf94e9U,
	0x8cbcce22U, 0x559fc06aU, 0xd268f536U, 0xe10af79aU,
	0xc1af4d69U, 0x1d2917b5U, 0xec4c304dU, 0x9ee5016cU,
	0x69232f74U, 0xfead7bb3U, 0xe9089ab6U, 0xf012f6aeU,
    };

    const unsigned char *str = key;
    hash_val_t acc = 0;

    while (*str) {
	acc ^= randbox[(*str + acc) & 0xf];
	acc = (acc << 1) | (acc >> 31);
	acc &= 0xffffffffU;
	acc ^= randbox[((*str++ >> 4) + acc) & 0xf];
	acc = (acc << 2) | (acc >> 30);
	acc &= 0xffffffffU;
    }
    return acc;
}

static int hash_comp_default(const void *key1, const void *key2)
{
    return strcmp(key1, key2);
}

#ifdef KAZLIB_TEST_MAIN

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

typedef char input_t[256];

static int tokenize(char *string, ...)
{
    char **tokptr; 
    va_list arglist;
    int tokcount = 0;

    va_start(arglist, string);
    tokptr = va_arg(arglist, char **);
    while (tokptr) {
	while (*string && isspace(*string))
	    string++;
	if (!*string)
	    break;
	*tokptr = string;
	while (*string && !isspace(*string))
	    string++;
	tokptr = va_arg(arglist, char **);
	tokcount++;
	if (!*string)
	    break;
	*string++ = 0;
    }
    va_end(arglist);

    return tokcount;
}

static char *dupstring(char *str)
{
    int sz = strlen(str) + 1;
    char *new = malloc(sz);
    if (new)
	memcpy(new, str, sz);
    return new;
}

static hnode_t *new_node(void *c)
{
    static hnode_t few[5];
    static int count;

    if (count < 5)
	return few + count++;

    return NULL;
}

static void del_node(hnode_t *n, void *c)
{
}

int main(void)
{
    input_t in;
    hash_t *h = hash_create(HASHCOUNT_T_MAX, 0, 0);
    hnode_t *hn;
    hscan_t hs;
    char *tok1, *tok2, *key, *val;
    int prompt = 0;

    char *help =
	"a <key> <val>          add value to hash table\n"
	"d <key>                delete value from hash table\n"
	"l <key>                lookup value in hash table\n"
	"n                      show size of hash table\n"
	"c                      show number of entries\n"
	"t                      dump whole hash table\n"
	"+                      increase hash table (private func)\n"
	"-                      decrease hash table (private func)\n"
	"b                      print hash_t_bit value\n"
	"p                      turn prompt on\n"
	"s                      switch to non-functioning allocator\n"
	"q                      quit";

    if (!h)
	puts("hash_create failed");

    for (;;) {
	if (prompt)
	    putchar('>');
	fflush(stdout);

	if (!fgets(in, sizeof(input_t), stdin))
	    break;

	switch(in[0]) {
	    case '?':
		puts(help);
		break;
	    case 'b':
		printf("%d\n", hash_val_t_bit);
		break;
	    case 'a':
		if (tokenize(in+1, &tok1, &tok2, (char **) 0) != 2) {
		    puts("what?");
		    break;
		}
		key = dupstring(tok1);
		if (!key) {
		    puts("dupstring failed");
		    break;
		}
		val = dupstring(tok2);
		if (!val) {
		    puts("dupstring failed");
		    free(key);
		    break;
		}
		if (!hash_alloc_insert(h, key, val)) {
		    puts("hash_alloc_insert failed");
		    free(key);
		    free(val);
		    break;
		}
		break;
	    case 'd':
		if (tokenize(in+1, &tok1, (char **) 0) != 1) {
		    puts("what?");
		    break;
		}
		hn = hash_lookup(h, tok1);
		if (!hn) {
		    puts("hash_lookup failed");
		    break;
		}
		key = hnode_get(hn);
		val = hnode_getkey(hn);
		hash_delete_free(h, hn);
		free(key);
		free(val);
		break;
	    case 'l':
		if (tokenize(in+1, &tok1, (char **) 0) != 1) {
		    puts("what?");
		    break;
		}
		hn = hash_lookup(h, tok1);
		if (!hn) {
		    puts("hash_lookup failed");
		    break;
		}
		val = hnode_get(hn);
		puts(val);
		break;
	    case 'n':
		printf("%lu\n", (unsigned long) hash_size(h));
		break;
	    case 'c':
		printf("%lu\n", (unsigned long) hash_count(h));
		break;
	    case 't':
		hash_scan_begin(&hs, h);
		while ((hn = hash_scan_next(&hs)))
		    printf("%s\t%s\n", (char*) hnode_getkey(hn),
			    (char*) hnode_get(hn));
		break;
	    case '+':
		grow_table(h);		/* private function	*/
		break;
	    case '-':
		shrink_table(h);	/* private function	*/
		break;
	    case 'q':
		exit(0);
		break;
	    case '\0':
		break;
	    case 'p':
		prompt = 1;
		break;
	    case 's':
		hash_set_allocator(h, new_node, del_node, NULL);
		break;
	    default:
		putchar('?');
		putchar('\n');
		break;
	}
    }

    return 0;
}

#endif
