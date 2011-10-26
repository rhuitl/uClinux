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
 * $Id: hash.h,v 1.1 2005-01-07 01:32:37 damion Exp $
 * $Name:  $
 */

#ifndef HASH_H
#define HASH_H

#include <limits.h>
#ifdef KAZLIB_SIDEEFFECT_DEBUG
#include "sfx.h"
#endif

/*
 * Blurb for inclusion into C++ translation units
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long hashcount_t;
#define HASHCOUNT_T_MAX ULONG_MAX

typedef unsigned long hash_val_t;
#define HASH_VAL_T_MAX ULONG_MAX

extern int hash_val_t_bit;

#ifndef HASH_VAL_T_BIT
#define HASH_VAL_T_BIT ((int) hash_val_t_bit)
#endif

/*
 * Hash chain node structure.
 * Notes:
 * 1. This preprocessing directive is for debugging purposes.  The effect is
 *    that if the preprocessor symbol KAZLIB_OPAQUE_DEBUG is defined prior to the
 *    inclusion of this header,  then the structure shall be declared as having
 *    the single member   int __OPAQUE__.   This way, any attempts by the
 *    client code to violate the principles of information hiding (by accessing
 *    the structure directly) can be diagnosed at translation time. However,
 *    note the resulting compiled unit is not suitable for linking.
 * 2. This is a pointer to the next node in the chain. In the last node of a
 *    chain, this pointer is null.
 * 3. This is a back-pointer to the primary pointer to this node.  The primary
 *    pointer is the previous node's next pointer to this node. If there is no
 *    previous node, the primary pointer is the pointer that resides in the
 *    hash table. This back-pointer lets us handle deletions easily without
 *    searching the chain.
 * 4. The key is a pointer to some user supplied data that contains a unique
 *    identifier for each hash node in a given table. The interpretation of
 *    the data is up to the user. When creating or initializing a hash table,
 *    the user must supply a pointer to a function for comparing two keys,
 *    and a pointer to a function for hashing a key into a numeric value.
 * 5. The value is a user-supplied pointer to void which may refer to
 *    any data object. It is not interpreted in any way by the hashing
 *    module.
 * 6. The hashed key is stored in each node so that we don't have to rehash
 *    each key when the table must grow or shrink.
 */

typedef struct hnode_t {
    #if defined(HASH_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)	/* 1 */
    struct hnode_t *next;	/* 2 */
    struct hnode_t **pself;	/* 3 */
    void *key;			/* 4 */
    void *data;			/* 5 */
    hash_val_t hkey;		/* 6 */
    #else
    int OPAQUE;
    #endif
} hnode_t;

/*
 * The comparison function pointer type. A comparison function takes two keys
 * and produces a value of -1 if the left key is less than the right key, a
 * value of 0 if the keys are equal, and a value of 1 if the left key is
 * greater than the right key.
 */

typedef int (*hash_comp_t)(const void *, const void *);

/*
 * The hashing function performs some computation on a key and produces an
 * integral value of type hash_val_t based on that key. For best results, the
 * function should have a good randomness properties in *all* significant bits
 * over the set of keys that are being inserted into a given hash table. In
 * particular, the most significant bits of hash_val_t are most significant to
 * the hash module. Only as the hash table expands are less significant bits
 * examined. Thus a function that has good distribution in its upper bits but
 * not lower is preferrable to one that has poor distribution in the upper bits
 * but not the lower ones.
 */

typedef hash_val_t (*hash_fun_t)(const void *);

/*
 * allocator functions
 */

typedef hnode_t *(*hnode_alloc_t)(void *);
typedef void (*hnode_free_t)(hnode_t *, void *);

/*
 * This is the hash table control structure. It keeps track of information
 * about a hash table, as well as the hash table itself.
 * Notes:
 * 1.  Pointer to the hash table proper. The table is an array of pointers to
 *     hash nodes (of type hnode_t). If the table is empty, every element of
 *     this table is a null pointer. A non-null entry points to the first
 *     element of a chain of nodes.
 * 2.  This member keeps track of the size of the hash table---that is, the
 *     number of chain pointers.
 * 3.  The count member maintains the number of elements that are presently
 *     in the hash table.
 * 4.  The maximum count is the greatest number of nodes that can populate this
 *     table. If the table contains this many nodes, no more can be inserted,
 *     and the hash_isfull() function returns true.
 * 5.  The high mark is a population threshold, measured as a number of nodes,
 *     which, if exceeded, will trigger a table expansion. Only dynamic hash
 *     tables are subject to this expansion.
 * 6.  The low mark is a minimum population threshold, measured as a number of
 *     nodes. If the table population drops below this value, a table shrinkage
 *     will occur. Only dynamic tables are subject to this reduction.  No table
 *     will shrink beneath a certain absolute minimum number of nodes.
 * 7.  This is the a pointer to the hash table's comparison function. The
 *     function is set once at initialization or creation time.
 * 8.  Pointer to the table's hashing function, set once at creation or
 *     initialization time.
 * 9.  The current hash table mask. If the size of the hash table is 2^N,
 *     this value has its low N bits set to 1, and the others clear. It is used
 *     to select bits from the result of the hashing function to compute an
 *     index into the table.
 * 10. A flag which indicates whether the table is to be dynamically resized. It
 *     is set to 1 in dynamically allocated tables, 0 in tables that are
 *     statically allocated.
 */

typedef struct hash_t {
    #if defined(HASH_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)
    struct hnode_t **table;			/* 1 */
    hashcount_t nchains;			/* 2 */
    hashcount_t count;				/* 3 */
    hashcount_t maxcount;			/* 4 */
    hashcount_t highmark;			/* 5 */
    hashcount_t lowmark;			/* 6 */
    hash_comp_t compare;			/* 7 */
    hash_fun_t hash;				/* 8 */
    hnode_alloc_t allocnode;
    hnode_free_t freenode;
    void *context;
    hash_val_t mask;				/* 9 */
    int dynamic;				/* 10 */
    #else
    int OPAQUE;
    #endif
} hash_t;

/*
 * Hash scanner structure, used for traversals of the data structure.
 * Notes:
 * 1. Pointer to the hash table that is being traversed.
 * 2. Reference to the current chain in the table being traversed (the chain
 *    that contains the next node that shall be retrieved).
 * 3. Pointer to the node that will be retrieved by the subsequent call to
 *    hash_scan_next().
 */

typedef struct hscan_t {
    #if defined(HASH_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)
    hash_t *hash;	/* 1 */
    hash_val_t chain;	/* 2 */
    hnode_t *next;	/* 3 */
    #else
    int OPAQUE;
    #endif
} hscan_t;

extern hash_t *hash_create(hashcount_t, hash_comp_t, hash_fun_t);
extern void hash_set_allocator(hash_t *, hnode_alloc_t, hnode_free_t, void *);
extern void hash_destroy(hash_t *);
extern void hash_free(hash_t *);
extern hash_t *hash_init(hash_t *, hashcount_t, hash_comp_t,
	hash_fun_t, hnode_t **, hashcount_t);
extern void hash_insert(hash_t *, hnode_t *, void *);
extern hnode_t *hash_lookup(hash_t *, void *);
extern hnode_t *hash_delete(hash_t *, hnode_t *);
extern int hash_alloc_insert(hash_t *, void *, void *);
extern void hash_delete_free(hash_t *, hnode_t *);

extern void hnode_put(hnode_t *, void *);
extern void *hnode_get(hnode_t *);
extern void *hnode_getkey(hnode_t *);
extern hashcount_t hash_count(hash_t *);
extern hashcount_t hash_size(hash_t *);

extern int hash_isfull(hash_t *);
extern int hash_isempty(hash_t *);

extern void hash_scan_begin(hscan_t *, hash_t *);
extern hnode_t *hash_scan_next(hscan_t *);
extern hnode_t *hash_scan_delete(hash_t *, hnode_t *);

extern int hash_verify(hash_t *);

extern hnode_t *hnode_create(void *);
extern hnode_t *hnode_init(hnode_t *, void *);
extern void hnode_destroy(hnode_t *);

#if defined(HASH_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)
#ifdef KAZLIB_SIDEEFFECT_DEBUG
#define hash_isfull(H) (SFX_CHECK(H)->count == (H)->maxcount)
#else
#define hash_isfull(H) ((H)->count == (H)->maxcount)
#endif
#define hash_isempty(H) ((H)->count == 0)
#define hash_count(H) ((H)->count)
#define hash_size(H) ((H)->nchains)
#define hnode_get(N) ((N)->data)
#define hnode_getkey(N) ((N)->key)
#define hnode_put(N, V) ((N)->data = (V))
#endif

#ifdef __cplusplus
}
#endif

#endif
