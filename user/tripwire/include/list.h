/* $Id: list.h,v 1.5 1994/07/15 11:02:53 gkim Exp $ */

/* #define LIST_HASHSZ	17011 */
#define LIST_HASHSZ	6007		/* a more reasonable hash size */

/* Thanks to Paul Hilchey for cleaning this up */

/* data node: these get linked into both a doubly linked list (using next
   and prev) and a chained hash table (using cnext) */
struct list_elem {
    char 	*varname;
    char	*varvalue;
    int		priority;
    int		flag;
    struct list_elem	*next;		/* pointer to next entry on list */
    struct list_elem	*prev;		/* pointer to prev entry on list */
    struct list_elem	*cnext;		/* pointer to next entry on chain */
};

/* hash list: NULL pointers are used instead of list/chain sentinels */
struct list {
    struct list_elem	*p_head;	/* head of linked list */
    struct list_elem	*p_tail;	/* tail of linked list */
    struct list_elem	*p_curr;	/* current element for list traversal */
    struct list_elem	*hashtable[LIST_HASHSZ];	/* hash chains */
};

typedef struct list list;

/* prototypes */
/* Do not remove this line.  Protyping depends on it! */
#if defined(__STDC__) || defined(__cplusplus)
#define P_(s) s
#else
#define P_(s) ()
#endif

/* list.c */
void list_set P_((char *pc_name, char *pc_value, int priority, struct list **pp_list));
char *list_lookup P_((char *pc_name, struct list **pp_list));
int list_isthere P_((char *pc_name, struct list **pp_list));
void list_unset P_((char *pc_name, struct list **pp_list));
int list_setflag P_((char *pc_name, int flag, struct list **pp_list));
int list_getflag P_((char *pc_name, struct list **pp_list));
void list_print P_((struct list **pp_list));
void list_reset P_((struct list **pp_list));
int list_init P_((void));
int list_open P_((struct list **pp_list));
struct list_elem *list_get P_((struct list **pp_list));
int list_close P_((struct list **pp_list));

#undef P_
