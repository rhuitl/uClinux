/*
*  sfxlist.h
*
*  Special LIST uses a memcap and splays nodes based on access
*
*  All of these functions are based on lists, which use
*  the standard malloc.
*
*  Note that NODE_DATA can be redifined with the
*  define below.
*
*/
#ifndef _SFLSQ_
#define _SFLSQ_

/*
*  
*/
typedef void * NODE_DATA;

/*
*    Simple list,stack or queue NODE
*/ 
typedef struct sf_lnode
{
  struct sf_lnode *next;
  struct sf_lnode *prev;
  NODE_DATA      ndata;
}
SF_QNODE,SF_SNODE,SF_LNODE;


/*
*	Integer Stack - uses an array from the subroutines stack
*/
typedef struct {
 unsigned *stack;
 int nstack;
 int n;
 int imalloc;
}
SF_ISTACK;
/*
*	Pointer Stack - uses an array from the subroutines stack
*/
typedef struct {
 void **stack;
 int nstack;
 int n;
 int imalloc;
}
SF_PSTACK;


/*
*  Simple Structure for Queue's, stacks, lists
*/ 
typedef struct sf_list
{
  SF_LNODE *head, *tail;  
  SF_LNODE *cur;  /* used for First/Next walking */
  int       count;
}
SF_QUEUE,SF_STACK,SF_LIST;



/*
*  Linked List Interface
*/ 
SF_LIST * sflist_new ( void ); 
void      sflist_init ( SF_LIST * s); 
int       sflist_add_tail ( SF_LIST* s, NODE_DATA ndata );
int       sflist_add_head ( SF_LIST* s, NODE_DATA ndata );
int       sflist_add_before ( SF_LIST* s, SF_LNODE * lnode, NODE_DATA ndata );
NODE_DATA sflist_remove_head ( SF_LIST * s);
NODE_DATA sflist_remove_tail ( SF_LIST * s); 
NODE_DATA sflist_remove_current ( SF_LIST * s); 
int       sflist_count ( SF_LIST* s); 
NODE_DATA sflist_first( SF_LIST * s);
NODE_DATA sflist_next( SF_LIST * s);
NODE_DATA sflist_prev( SF_LIST * s);
SF_LNODE *sflist_first_node( SF_LIST * s );
SF_LNODE *sflist_next_node( SF_LIST * s );
void      sflist_free ( SF_LIST * s); 
void      sflist_free_all( SF_LIST * s, void (*free)(void*) ); 

/*
*   Stack Interface ( LIFO - Last in, First out ) 
*/
SF_STACK *sfstack_new ( void ); 
void      sfstack_init ( SF_STACK * s); 
int       sfstack_add( SF_STACK* s, NODE_DATA ndata ); 
NODE_DATA sfstack_remove ( SF_STACK * s);
int       sfstack_count ( SF_STACK * s); 
void      sfstack_free ( SF_STACK * s); 
void      sfstack_free_all( SF_STACK* s, void (*free)(void*) ); 

/*
*   Queue Interface ( FIFO - First in, First out ) 
*/
SF_QUEUE *sfqueue_new ( void ); 
void      sfqueue_init ( SF_QUEUE * s); 
int       sfqueue_add( SF_QUEUE * s, NODE_DATA ndata ); 
NODE_DATA sfqueue_remove ( SF_QUEUE * s);
int       sfqueue_count ( SF_QUEUE * s); 
void      sfqueue_free ( SF_QUEUE * s); 
void      sfqueue_free_all( SF_QUEUE* s, void (*free)(void*) ); 

/*
* Performance Stack functions for Integer/Unsigned and Pointers, uses
* user provided array storage, perhaps from the program stack or a global.
* These are efficient, and use no memory functions.
*/
int sfistack_init( SF_ISTACK * s, unsigned * a,  int n  );
int sfistack_push( SF_ISTACK *s, unsigned value);
int sfistack_pop(  SF_ISTACK *s, unsigned * value);

int sfpstack_init( SF_PSTACK * s, void ** a,  int n  );
int sfpstack_push( SF_PSTACK *s, void * value);
int sfpstack_pop(  SF_PSTACK *s, void ** value);

#endif
