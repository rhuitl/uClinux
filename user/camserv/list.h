/*
 * List Abstract Data Type
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
 * $Id: list.h,v 1.1 2005-01-07 01:32:37 damion Exp $
 * $Name:  $
 */

#ifndef LIST_H
#define LIST_H

#include <limits.h>

#ifdef KAZLIB_SIDEEFFECT_DEBUG
#include "sfx.h"
#else
#define SFX_CHECK(E) (E)
#endif

/*
 * Blurb for inclusion into C++ translation units
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long listcount_t;
#define LISTCOUNT_T_MAX ULONG_MAX

typedef struct lnode_t {
    #if defined(LIST_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)
    struct lnode_t *next;
    struct lnode_t *prev;
    void *data;
    #else
    int OPAQUE;
    #endif
} lnode_t;

typedef struct lnodepool_t {
    #if defined(LIST_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)
    struct lnode_t *pool;
    struct lnode_t *fre;
    listcount_t size;
    #else
    int OPAQUE;
    #endif
} lnodepool_t;

typedef struct list_t {
    #if defined(LIST_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)
    lnode_t nilnode;
    listcount_t count;
    listcount_t maxcount;
    #else
    int OPAQUE;
    #endif
} list_t;

lnode_t *lnode_create(void *);
lnode_t *lnode_init(lnode_t *, void *);
void lnode_destroy(lnode_t *);
void lnode_put(lnode_t *, void *);
void *lnode_get(lnode_t *);
int lnode_is_in_a_list(lnode_t *);

#if defined(LIST_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)
#define lnode_put(N, D)		((N)->data = (D))
#define lnode_get(N)		((N)->data)
#endif

lnodepool_t *lnode_pool_init(lnodepool_t *, lnode_t *, listcount_t);
lnodepool_t *lnode_pool_create(listcount_t);
void lnode_pool_destroy(lnodepool_t *);
lnode_t *lnode_borrow(lnodepool_t *, void *);
void lnode_return(lnodepool_t *, lnode_t *);
int lnode_pool_isempty(lnodepool_t *);
int lnode_pool_isfrom(lnodepool_t *, lnode_t *);

list_t *list_init(list_t *, listcount_t);
list_t *list_create(listcount_t);
void list_destroy(list_t *);
void list_destroy_nodes(list_t *);
void list_return_nodes(list_t *, lnodepool_t *);

listcount_t list_count(list_t *);
int list_isempty(list_t *);
int list_isfull(list_t *);
int list_contains(list_t *, lnode_t *);

void list_append(list_t *, lnode_t *);
void list_prepend(list_t *, lnode_t *);
void list_ins_before(list_t *, lnode_t *, lnode_t *);
void list_ins_after(list_t *, lnode_t *, lnode_t *);

lnode_t *list_first(list_t *);
lnode_t *list_last(list_t *);
lnode_t *list_next(list_t *, lnode_t *);
lnode_t *list_prev(list_t *, lnode_t *);

lnode_t *list_del_first(list_t *);
lnode_t *list_del_last(list_t *);
lnode_t *list_delete(list_t *, lnode_t *);

void list_process(list_t *, void *, void (*)(list_t *, lnode_t *, void *));

int list_verify(list_t *);

#if defined(LIST_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)
#define lnode_pool_isempty(P)	((P)->fre == 0)
#define list_count(L)		((L)->count)
#define list_isempty(L)		(SFX_CHECK(L)->count == 0)
#define list_isfull(L)		(SFX_CHECK(L)->count == (L)->maxcount)
#define list_next(L, N)		(SFX_CHECK(N)->next == &(L)->nilnode ? NULL : (N)->next)
#define list_prev(L, N)		(SFX_CHECK(N)->prev == &(L)->nilnode ? NULL : (N)->prev)
#define list_first(L)		list_next(SFX_CHECK(L), &(L)->nilnode)
#define list_last(L)		list_prev(SFX_CHECK(L), &(L)->nilnode)
#endif

#if defined(LIST_IMPLEMENTATION) || !defined(KAZLIB_OPAQUE_DEBUG)
#define list_append(L, N)	list_ins_before(SFX_CHECK(L), N, &(L)->nilnode)
#define list_prepend(L, N)	list_ins_after(SFX_CHECK(L), N, &(L)->nilnode)
#define list_del_first(L)	list_delete(SFX_CHECK(L), list_first(L))
#define list_del_last(L)	list_delete(SFX_CHECK(L), list_last(L))
#endif

/* destination list on the left, source on the right */

void list_extract(list_t *, list_t *, lnode_t *, lnode_t *);
void list_transfer(list_t *, list_t *, lnode_t *first);
void list_merge(list_t *, list_t *, int (const void *, const void *));
void list_sort(list_t *, int (const void *, const void *));
int list_is_sorted(list_t *, int (const void *, const void *));

#ifdef __cplusplus
}
#endif

#endif
