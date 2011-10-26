#ifndef lint
static char rcsid[] = "$Id: list.c,v 1.14 1994/07/17 01:13:53 gkim Exp $";
#endif

/*
 * list.c
 *
 *	generic linked list routines.
 *
 *	These routines generally use a (struct list **) as an argument
 *	(ie: a pointer to a pointer to the head of the list).  This way,
 *	a NULL list pointer will automatically be malloc()'d into existence.
 *
 *	These routines started as extremely simple routines.  Unfortunately, the
 *	O(n) search times made Tripwire extremely slow.  So, v3.1 of
 *	the linked list routines incorporate a hash table into each of
 *	the list structures.  *whew*  It's faster, but it's not simple
 *	anymore.  (The addition of back pointers didn't help either...)
 *
 *	Why?  Well, we need to preserve order for the list of generated files.
 *	So, a hash table won't do, and a simple linked list is too slow.
 *
 * Gene Kim
 * Purdue University
 *
 * March 1994 - Reworked to fix various bugs.	
 *				Paul Hilchey, UBC, hilchey@ucs.ubc.ca
 *
 ********** testing schedule ************
 *
 *	hashtable size = 1
 *	num records = 500		OK
 *
 *	hashtable size = 1
 *	num records = 2000		OK		
 *
 *	hashtable size = 6007
 *	num records = 50		OK
 *
 *	hashtable size = 6007
 *	num records = 3000		OK
 *
 *	hashtable size = 6007
 *	num records = 8000		OK
 *
 *	hashtable size = 6007
 *	num records = 20000	
 *
 * ghk -- 03/20/94
 */

#include "../include/config.h"
#include <stdio.h>
#ifdef STDLIBH
#include <stdlib.h>
#endif
#include <assert.h>
#ifdef MALLOCH
# include <malloc.h>
#endif
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#include "../include/list.h"

/* prototypes */
static unsigned int string_hash ();

static int listdebug = 0;

#define LISTDEBUG(x) if (listdebug >= (x))

/*
 * list_set(pc_name, pc_value, priority, pp_list)
 *
 *	insert structure with (name=pc_name) and (value=pc_value)
 *	into the specified list
 */

void
list_set(pc_name, pc_value, priority, pp_list)
    int priority;
    char *pc_name, *pc_value;
    struct list **pp_list;
{
    struct list_elem *p, *sp, **q, **chain;
    int i, foundit;
    int namesize, valuesize;
    char *saved_pcname = NULL;

    /* were we handed a NULL list pointer? */
    if (*pp_list == NULL) {
	/* malloc hash table */
	if (NULL == (*pp_list = (struct list *)malloc(sizeof(struct list)))) {
		fprintf(stderr, "list_insert(): malloc() failed!\n");
		exit(1);
	}

	/* initialize it */
	for (i=0; i<LIST_HASHSZ; i++)
		(*pp_list)->hashtable[i] = (struct list_elem *)NULL;

	(*pp_list)->p_head = (*pp_list)->p_tail = (*pp_list)->p_curr = 
		(struct list_elem *)NULL;
    }
	
    /* chain points to the pointer to the first element in the chain */
    chain = &( ((*pp_list)->hashtable)[string_hash(pc_name)] );

    /*
     * 1) if pc_name is already in the list, then we compare priority
     *		levels.  replace only if new priority is higher than
     *		existing priority.
     *
     * 2) if pc_name is not on the list, then we just add it to the
     *		end of the list
     */

    namesize = strlen(pc_name) + 1;	/* +1 for the terminating \0 */
    valuesize = strlen(pc_value) + 1;
    foundit = 0;

    /* walk through hash chain: p -> current element, q -> the link pointing to p */
    for (p = *chain, q = chain; p; q = &(p->cnext), p = p->cnext) {
	if (strcmp(p->varname, pc_name) == 0) {
	    /*
	     * if existing priority is equal or less than this one,
	     * then go ahead and clobber it.
	     */
LISTDEBUG(10)
fprintf(stderr, "list_set(): '%s' variable already found..\n", pc_name);
	    if (p->priority <= priority) {

LISTDEBUG(10)
fprintf(stderr, "list_set(): Clobbering...\n");
		foundit = 1;
		break;
	    }
	    /* existing priority is higher so do nothing */
	    return;
	}
    }

    if (foundit) {
	/* p -> found node; q points to pointer to p */
        /* reallocate it and update links as needed */
	sp = p;

	/* bad things happen if (pc_name) is freed by realloc().  so, we
	 * detect this situation, and save a copy.
	 */

	if (pc_name == (char *)p + sizeof(struct list_elem)) {
	    if (!(saved_pcname = malloc(namesize))) {
		fprintf(stderr, "list_insert(): malloc() failed!\n");
		exit(1);
	    }
	    strcpy(saved_pcname, pc_name);
	}
	 
	p = (struct list_elem *) realloc(p, sizeof(struct list_elem) + namesize + valuesize);
	if (p == NULL) {
		fprintf(stderr, "list_insert(): realloc() failed!\n");
		exit(1);
	}
	/* update pointers only if it moved */
	if (sp != p) {
		if (p->next)
			p->next->prev = p;
		if (p->prev)
			p->prev->next = p;
		(*q) = p;
		if (sp == (*pp_list)->p_tail)
			(*pp_list)->p_tail = p;
		if (sp == (*pp_list)->p_head)
			(*pp_list)->p_head = p;
		if (sp == (*pp_list)->p_curr)
			(*pp_list)->p_curr = p;
	}
    } else {
        /* create new element */
        if ((p = (struct list_elem *) malloc(sizeof(struct list_elem) + namesize + valuesize))
        				== NULL) {
            fprintf(stderr, "list_insert(): malloc() failed!\n");
            exit(1);
        }
    
        /* link it onto list and hash chain */
        p->next = NULL;
        p->prev = (*pp_list)->p_tail;
        if (p->prev) 
        	p->prev->next = p;
        else
    	(*pp_list)->p_head = p;
        (*pp_list)->p_tail = p;
        p->cnext = *chain;
        *chain = p;
    }

    /* fill in data fields */
    p->varname = (char *)p + sizeof(struct list_elem);

    if (!saved_pcname)
	(void) strcpy(p->varname, pc_name);
    else {
	(void) strcpy(p->varname, saved_pcname);
	free(saved_pcname);
    }

    if (!foundit) {
	p->flag = 0;
	p->priority = priority;
    }

    p->varvalue = p->varname + namesize;
    (void) strcpy(p->varvalue, pc_value);

    return;

}

/*
 * char *
 * list_lookup(pc_name, pp_list)
 *
 *	return the string value assigned to the environment value named
 *	pc_name in the specified list.
 *
 *	you must copy the contents of the (char *).
 */

char *
list_lookup(pc_name, pp_list)
    char *pc_name;
    struct list **pp_list;
{
    struct list_elem *p, **q;
    char	*s;

    /*
     * 1) if *pp_list is NULL, then we know it's emtpy
     * 2) if it's not in the hash table, then return NULL
     * 3) search hash table chain
     */

    /* check for empty list */
    if (*pp_list == NULL) {
	return NULL;
    }

    q = &( ((*pp_list)->hashtable)[string_hash(pc_name)] );

    /* now search through hash chain */
    for (p = *q; p; p = p->cnext) {
	if (strcmp(p->varname, pc_name) == 0) {
	    s = p->varvalue;
	    return s;
	}
    }
    return NULL;
}

/*
 * int
 * list_isthere(pc_name, pp_list)
 *
 *	returns (1) if pc_name is in the specified list.
 *	else returns (0).
 */

int
list_isthere(pc_name, pp_list)
    char *pc_name;
    struct list **pp_list;
{
    struct list_elem *p, **q;

    /*
     * 1) if *pp_list is NULL, then we know it's emtpy
     * 3) search hash table chain
     */

    /* check for empty list */
    if (*pp_list == NULL) {
	return 0;
    }

    q = &( ((*pp_list)->hashtable)[string_hash(pc_name)] );

    /* now search through hash chain */
    for (p = *q; p; p = p->cnext) {
	if (strcmp(p->varname, pc_name) == 0) {
	    return 1;
	}
    }
    return 0;
}

/*
 * list_unset(pc_name, pp_list)
 *	remove the list entry with (varname == pcname) from the
 *	environment
 */

void
list_unset(pc_name, pp_list)
    char *pc_name;
    struct list **pp_list;
{
    struct list_elem *p, **q;

    if (*pp_list == NULL)
	return;

    /*
     * 1) if pc_name isn't found in the hash chain, return
     * 2) if found, remove the element from the list, and then remove
     *		from hash chain.
     */

    /* look in hash table */
    q = &(((*pp_list)->hashtable)[string_hash(pc_name)]);

    /* find the element, but playing pointer tag w/two pointers */
    for (p = *q; p; q = &(p->cnext), p = p->cnext) {
	if (strcmp(p->varname, pc_name) == 0) {
	    /* remove the element from the list */

	    /* are we at the head of the list? */
	    if (p->prev) 
		p->prev->next = p->next;
	    else
		(*pp_list)->p_head = p->next;
	
	    /* are we at the end of the list? */
	    if (p->next) 
		p->next->prev = p->prev;
	    else
		(*pp_list)->p_tail = p->prev;

	    /* are we the current item? */
	    if (p == (*pp_list)->p_curr)
		(*pp_list)->p_curr = p->next;

	    /* now remove from hash chain */
	    *q = p->cnext;
	    free((char *) p);
	    return;
	}
    }
}

/*
 * list_setflag(pc_name, flag, pp_list)
 *
 *	OR the the specified flag to the existing flag value.
 */

int
list_setflag(pc_name, flag, pp_list)
    char *pc_name;
    int	flag;
    struct list **pp_list;
{
    struct list_elem *p, **q;

    if (*pp_list == NULL)
	return -1;

    /*
     * 1) look in hash table for entry.  if not found, return with error.
     * 2) walk down hash chain until entry is found, then modify the
     *		list entry
     */

    q = &( ((*pp_list)->hashtable)[string_hash(pc_name)] );

    /* walk down chain */
    for (p = *q; p; p = p->cnext) {
	if (strcmp(p->varname, pc_name) == 0) {
	    p->flag |= flag;
	    return 0;
	}
    }

    return 0;
}

/*
 * list_getflag(pc_name, pp_list)
 *	return the flag value embedded in structure.
 */

int
list_getflag(pc_name, pp_list)
    char *pc_name;
    struct list **pp_list;
{

    struct list_elem *p, **q;

    if (*pp_list == NULL)
	return -1;

    /*
     * 1) look in hash table for entry.  if not found, return with error.
     * 2) walk down hash chain until entry is found, then modify the
     *		list entry
     */

    q = &( ((*pp_list)->hashtable)[string_hash(pc_name)] );

    /* walk down chain */
    for (p = *q; p; p = p->cnext) {
	if (strcmp(p->varname, pc_name) == 0) {
	    return p->flag;
	}
    }

    return -1;
}

/*
 * list_print()
 *	print out the entire contents of the linked list
 */

void
list_print(pp_list)
    struct list **pp_list;
{
    struct list_elem	*p;
    struct list_elem *head;

    /* check to see if list is empty */
    if (*pp_list == NULL)
	return;
	
    head = (*pp_list)->p_head;

    /* walk down entire list */
    for (p = head; p; p = p->next) {
	/*
	printf("%-40s\t%20s %d\n", p->varname, p->varvalue, p->flag);
	*/
	printf("(%s) %20s %d\n", p->varname, p->varvalue, p->flag);
    }
    return;
}

/*
 * list_reset()
 *	
 *	given a pointer to a list, delete the entire list, and set the
 *	pointer to NULL;
 */

void
list_reset (pp_list)
    struct list **pp_list;
{
    struct list_elem *p, *q;

    if (*pp_list == NULL)
	return;

    /* walk down the list, deleting the element that we just came from */
    for (p = (*pp_list)->p_head; p; q = p, p = p->next, free((char *) q)) ;

    /* now free up the list structure */
    free((char *) *pp_list);

    /* now invalidate the list structure pointer */
    *pp_list = NULL;

    return;
}


/*
 * list_init ()
 * list_open (struct list **pp_list)
 * list_get  (struct list **pp_list)
 * list_close(struct list **pp_list)
 *
 *	this allows the retrieval of individual list elements through
 *	successive calls to list_get().
 *
 *	0)	list_init() no-op
 *	1) 	list_open() sets the current pointer to the first element
 *	2) 	any calls to list_get() will get the next element. 
 *	3) 	list_close() clears current pointer
 */

int
list_init()
{
    return 0;
}

/*
 * list_open(struct list **pp_list)
 *
 *	reset current pointer to start of list
 */

int
list_open (pp_list)
    struct list **pp_list;
{
    /* is the list NULL? */
    if (*pp_list == NULL) {
	return 0;				/* we'll fake it later on */
    }

    (*pp_list)->p_curr = (*pp_list)->p_head;

    return 0;
}

/*
 * struct list_elem *
 * list_get(struct list **pp_list)
 *
 *	get the next entry in the specified list (using *pp_list as the key),
 *		and bump the internal pointer to the next element, ready
 *		for the next call to list_get().
 *	we return NULL if we're sitting on the tail end of the list.
 */

struct list_elem *
list_get (pp_list)
    struct list **pp_list;
{
    struct list_elem *p;

    /* fake it if you pass it a NULL */
    if (*pp_list == NULL) {
	return NULL;
    }

    p = (*pp_list)->p_curr;
    if (p)
	(*pp_list)->p_curr = p->next;
    return (p);
}

/*
 * list_close(struct list **pp_list)
 *	
 */

int
list_close (pp_list)
    struct list **pp_list;
{
    /* fake it if you pass it a NULL */
    if (*pp_list == NULL) {
	return 0;
    }

    (*pp_list)->p_curr = NULL;
    return 0;
}

static unsigned int
string_hash (string)
    char *string;
{
    unsigned int hindex;
    char *pc = string;

    hindex = *pc;
    while (*pc) {
	hindex = ((hindex << 9) ^ *pc++) % LIST_HASHSZ;
	/*
	hindex = ((hindex << 7) | (string[i] + len)) % LIST_HASHSZ;
	*/
    }
    return hindex;
}

#ifdef TEST
main()
{
    char s[1024];
    struct list *list = (struct list *) NULL;
    FILE *fpin;
    struct list_elem *p;
    int i, count, total[11];

#define X1
#ifdef X1
    if (!(fpin = fopen("/tmp/x", "r"))) {
	perror("fopen()");
	exit(1);
    }

    while (fgets(s, 1024, fpin) != 0) {
	s[strlen(s)-1] = 0;
	list_set(s, "", 0, &list);
	if (!list_lookup("/scr/genek/mush/expr.c", &list)) {
	    printf("Yikes!  (%s)\n", s);
	}
    }

    fseek(fpin, 0, 0);
    while (fgets(s, 1024, fpin) != 0) {
	s[strlen(s)-1] = 0;
	list_set(s, "x", 0, &list);
	if (!list_lookup("/scr/genek/mush/expr.c", &list)) {
	    printf("Yikes!  (%s)\n", s);
	}
    }
    fseek(fpin, 0, 0);

    while (fgets(s, 1024, fpin) != 0) {
	s[strlen(s)-1] = 0;
	if (!list_lookup(s, &list)) {
	    printf("Yikes!  (%s)\n", s);
	}
    }

    for (i=0; i<LIST_HASHSZ; i++) {
	count = 0;
	for (p=list->hashtable[i]; p; p=p->cnext)
		count++;
	if (count > 10)
		count = 10;
	total[count]++;
    }
    printf("\n\nlen   number\n");
    for (i=0; i<=10; i++)
	printf("%3d   %6d\n", i, total[i]);

#endif
}
#endif

#ifdef TEST2
main()
{
    struct list *l = NULL;

    list_set("a", "A", 1, &l);
    list_set("b", "B", 2, &l);
    list_set("c", "C", 3, &l);
    list_set("d", "d", 4, &l);
    list_set("e", "E", 5, &l);
    list_print(&l);
    list_set("d", "D", 5, &l);
    list_set("c", "c", 2, &l);
    list_setflag("b", 42, &l);
    list_print(&l);
    list_unset("a", &l);
    list_print(&l);
    list_unset("b", &l);
    list_print(&l);
    list_unset("d", &l);
    list_print(&l);
}
#endif /* TEST2 */

#ifdef TEST2
main()
{
    struct list *l = NULL;

    list_set("a", "", 0, &l);
    list_set("b", "", 0, &l);
    list_set("c", "", 0, &l);
    list_set("d", "", 0, &l);
    list_set("e", "", 0, &l);
    list_print(&l);
    list_unset("a", &l);
    list_print(&l);
    list_unset("b", &l);
    list_print(&l);
    list_unset("d", &l);
    list_print(&l);
}
#endif /* TEST2 */

#ifdef TEST1a
#define HSZ 50

list_debug_dump(pl)
    list *pl;
{
    struct list_elem *ph, *qh;
    static int table[HSZ];
    int i;
    int count = 0;

    for (i = 0; i < LIST_HASHSZ; i++) {
	ph = pl->hashtable[i];

	/* skip useless entries */
	if (!ph)
	    continue;

	for (qh = ph; qh; qh = qh->cnext) {
	    int tmp;
	    sscanf(qh->varname, "%d", &tmp);
	    table[tmp] = 1;
	    count++;
	}
    }

    printf("count=%d (expecting %d)\n", count, HSZ);

    for (i = 0; i < HSZ; i++) {
	if (!table[i])
	    printf("we lost bucket %d\n", i);
    }

}

main()
{
    static int isset[HSZ];
    int i, j;
    struct list *l = NULL;
    char name[1024];
    char *string = "x";
    int numleft;

    /* set all values */
    printf("--> set list\n");
    for (i = 0; i < HSZ; i++) {
	sprintf(name, "%d", i);
	list_set(name, string, 0, &l);
	isset[i] = 1;

    }

    /* check for fully connected hash table */
    printf("checking for connections...\n");
    list_debug_dump(l);

    /* elim one at a time, and check to see that it's gone */
    printf("--> eliminating\n");
    numleft = HSZ;
    while (numleft > 0) {
	int which = rand() % HSZ;

	if (!isset[which])
	    continue;

	sprintf(name, "%d", which);
	list_set(name, "", 14, &l);
	list_setflag(name, 1, &l);
	list_unset(name, &l);
	isset[which] = 0;
	numleft--;

#if HSZ < 50
	/* confirm order */
	printf("--> confirming order\n");
	list_open(&l);
	{
	    int pi;

	    for (pi = 0; !isset[pi]; pi++) ;

	    for (i = 0; i < numleft; i++) {
		struct list_elem *pl;
		char t[1024];

		pl = list_get(&l);
		sprintf(t, "%d", pi);
		if (strcmp(t, pl->varname)) {
		    printf("ordering fuck up!  pi=%d, list=%s\n", pi,
				pl->varname);
		    exit(1);
		}

		/* find next existing entry */
		for (pi++; !isset[pi]; pi++) ;
	    }
	}
	list_close(&l);
#endif

	/* skip if we're not close to failure case */

	/*
	if (numleft > 14005)
	    continue;
	    */

	for (j = 0; j < HSZ; j++) {
	    sprintf(name, "%d", j);
	    if (!isset[j]) {
		if(list_isthere(name, &l)) {
		    printf("fuck up -- list existing: j=%d\n", j);
		    exit(1);
		}
	    } else {
#if HSZ < 3000
		if(!list_isthere(name, &l)) {
		    printf("fuck up -- list not existing: j=%d\n", j);
		    exit(1);
		}
#else
		;
#endif
	    }
	}
	if (numleft % 10 == 0)
	    printf("numleft = %d\n", numleft);
    }

    printf("** SUCCESS **\n");
    exit(0);


}
#endif
