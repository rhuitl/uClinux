/*
*   sflsq.c    
*
*   Simple list, stack, queue, and dictionary implementations 
*   ( most of these implementations are list based - not performance monsters,
*     and they all use malloc via s_malloc/s_free )
*
*   Stack based Ineteger and Pointer Stacks, these are for
*   performance.(inline would be better)
*
*   Copyright(C) 2003 Sourcefire,Inc
*   Marc Norton
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sflsq.h"

/*
*  private malloc
*/ 
static void * s_malloc (int n) 
{
  void *p=0;
  if( n > 0 )p = (void*) malloc( n );
  return p;
}

/*
*  private free
*/ 
static void s_free (void *p) 
{
  if( p ) free( p );
}

/*
*   INIT - called by the NEW functions
*/ 
void sflist_init ( SF_LIST * s) 
{
  s->count=0; 
  s->head = s->tail = s->cur = 0;
}

/*
*    NEW
*/
SF_LIST * sflist_new() 
{
   SF_LIST * s;
   s = (SF_LIST*)s_malloc( sizeof(SF_LIST) );
   if( s )sflist_init( s );
   return s;
}

SF_STACK * sfstack_new() 
{
   return (SF_STACK*)sflist_new();
}

SF_QUEUE * sfqueue_new() 
{
   return (SF_QUEUE*)sflist_new();
}


/*
*     ADD to List/Stack/Queue/Dictionary
*/
/*
*  Add-Head Item 
*/ 
int 
sflist_add_head ( SF_LIST* s, NODE_DATA ndata )
{
  SF_LNODE * q;
  if (!s->head)
    {
      q = s->tail = s->head = (SF_LNODE *) s_malloc (sizeof (SF_LNODE));
      if(!q)return -1;
      q->ndata = (NODE_DATA)ndata;
      q->next = 0;
      q->prev = 0;
    }
  else
    {
      q = (SF_LNODE *) s_malloc (sizeof (SF_LNODE));
      if(!q)return -1;
      q->ndata = ndata;
      q->next = s->head;
      q->prev = 0;
      s->head->prev = q;
      s->head = q;

    }
  s->count++;

  return 0;
}

/*
*  Add-Tail Item 
*/ 
int 
sflist_add_tail ( SF_LIST* s, NODE_DATA ndata )
{
  SF_LNODE * q;
  if (!s->head)
    {
      q = s->tail = s->head = (SF_LNODE *) s_malloc (sizeof (SF_LNODE));
      if(!q)return -1;
      q->ndata = (NODE_DATA)ndata;
      q->next = 0;
      q->prev = 0;
    }
  else
    {
      q = (SF_LNODE *) s_malloc (sizeof (SF_LNODE));
      if(!q)return -1;
      q->ndata = ndata;
      q->next = 0;
      q->prev = s->tail;
      s->tail->next = q;
      s->tail = q;
    }
  s->count++;

  return 0;
}
/*
*  Add-Head Item 
*/ 
int sflist_add_before ( SF_LIST* s, SF_LNODE * lnode, NODE_DATA ndata )
{
  SF_LNODE * q;

  if( !lnode )
      return 0;

  /* Add to head of list */
  if( s->head == lnode )
  {
      return sflist_add_head ( s, ndata );
  }
  else
  {
      q = (SF_LNODE *) s_malloc ( sizeof (SF_LNODE) );
      if( !q )
      {
          return -1;
      }
      q->ndata = (NODE_DATA)ndata;

      q->next = lnode;
      q->prev = lnode->prev;
      lnode->prev->next = q;
      lnode->prev       = q;
  }
  s->count++;

  return 0;
}

/*
*/
int sfqueue_add(SF_QUEUE * s, NODE_DATA ndata ) 
{
  return sflist_add_tail ( s, ndata );
}

int sfstack_add( SF_STACK* s, NODE_DATA ndata ) 
{
  return sflist_add_tail ( s, ndata );
}

/* 
*   List walk - First/Next - return the node data or NULL
*/
NODE_DATA sflist_first( SF_LIST * s )
{
    s->cur = s->head;
    if( s->cur ) 
        return s->cur->ndata;
    return 0;
}
NODE_DATA sflist_next( SF_LIST * s )
{
    if( s->cur )
    {
        s->cur = s->cur->next;
        if( s->cur ) 
            return s->cur->ndata;
    }
    return 0;
}
NODE_DATA sflist_prev( SF_LIST * s )
{
    if( s->cur )
    {
        s->cur = s->cur->prev;
        if( s->cur ) 
            return s->cur->ndata;
    }
    return 0;
}
/* 
*   List walk - First/Next - return the node data or NULL
*/
SF_LNODE * sflist_first_node( SF_LIST * s )
{
    s->cur = s->head;
    if( s->cur ) 
        return s->cur;
    return 0;
}
SF_LNODE * sflist_next_node( SF_LIST * s )
{
    if( s->cur )
    {
        s->cur = s->cur->next;
        if( s->cur ) 
            return s->cur;
    }
    return 0;
}

/*
*  Remove Head Item from list
*/ 
NODE_DATA sflist_remove_head (SF_LIST * s) 
{
  NODE_DATA ndata = 0;
  SF_QNODE * q;
  if (s->head)
    {
      q = s->head;
      ndata = q->ndata;
      s->head = s->head->next;
      s->count--;
      if (!s->head)
	  {
	    s->tail = 0;
	    s->count = 0;
	  }
      s_free( q );
    }
  return (NODE_DATA)ndata;
}

/*
*  Remove tail Item from list
*/ 
NODE_DATA sflist_remove_tail (SF_LIST * s) 
{
  NODE_DATA ndata = 0;
  SF_QNODE * q;
  if (s->tail)
    {
      q = s->tail;

      ndata = q->ndata;
      s->count--;
      s->tail = q->prev; 
      if (!s->tail)
      {
	    s->tail = 0;
        s->head = 0;
	    s->count = 0;
      }
      else 
      {
        q->prev->next = 0;
      }
      s_free (q);
    }
  return (NODE_DATA)ndata;
}

/*
 * Written to remove current node from an SFLIST
 * MFR - 29May04
 */
NODE_DATA sflist_remove_current (SF_LIST * s) 
{
    NODE_DATA ndata = NULL;
    SF_LNODE *l;

    l = s->cur;
    
    if(l)
    {
        ndata = l->ndata;

        if(l->prev)
        {
            l->prev->next = l->next;
            s->cur = l->prev;
        }
        else
        {
            s->head = l->next;
            s->cur = l->next;
        }

        if(l->next)
            l->next->prev = l->prev;
        else
            s->tail = l->prev;

        s->count--;
        s_free(l);
        return (NODE_DATA)ndata;
    }

    return NULL;
}


/*
*  Remove Head Item from queue
*/ 
NODE_DATA sfqueue_remove (SF_QUEUE * s) 
{
  return (NODE_DATA)sflist_remove_head( s );
}

/*
*  Remove Tail Item from stack
*/ 
NODE_DATA sfstack_remove (SF_QUEUE * s) 
{
  return (NODE_DATA)sflist_remove_tail( s );
}

/*
*  COUNT
*/ 
int sfqueue_count (SF_QUEUE * s) 
{
  if(!s)return 0;
  return s->count;
}
int sflist_count ( SF_LIST* s) 
{
  if(!s)return 0;
  return s->count;
}
int sfstack_count ( SF_STACK * s) 
{
  if(!s)return 0;
  return s->count;
}


/*
*   Free List + Free it's data nodes using 'nfree' 
*/
void sflist_free_all( SF_LIST * s, void (*nfree)(void*) ) 
{
  void * p;
  while( sflist_count(s) )
  {
    p = sflist_remove_head (s);
	if(p)nfree(p);
  }
}
void sfqueue_free_all(SF_QUEUE * s,void (*nfree)(void*) ) 
{
  sflist_free_all( s, nfree ); 
}
void sfstack_free_all(SF_STACK * s,void (*nfree)(void*) ) 
{
  sflist_free_all( s, nfree ); 
}

/*
*  FREE List/Queue/Stack/Dictionary
*
*  This does not free a nodes data
*/ 
void sflist_free (SF_LIST * s)
{
  while( sflist_count(s) )
  {
    sflist_remove_head (s);
  }
}
void sfqueue_free (SF_QUEUE * s) 
{
  sflist_free ( s ); 
}
void sfstack_free (SF_STACK * s)
{
  sflist_free ( s ); 
}

/*
*   Integer stack functions - for performance scenarios
*/
int sfistack_init( SF_ISTACK * s, unsigned * a,  int n  )
{
   s->imalloc=0;
   if( a ) s->stack = a;
   else
   {
      s->stack = (unsigned*) malloc( n * sizeof(unsigned) );
      s->imalloc=1;
   }
   if( !s->stack ) return -1;
   s->nstack= n;
   s->n =0;
   return 0;
}
int sfistack_push( SF_ISTACK *s, unsigned value)
{
   if( s->n < s->nstack )
   {
       s->stack[s->n++] = value;
       return 0;
   }
   return -1;
}
int sfistack_pop( SF_ISTACK *s, unsigned * value)
{
   if( s->n > 0 )
   {
       s->n--;
       *value = s->stack[s->n];
       return 0;
   }
   return -1;
}

/*
*  Pointer Stack Functions - for performance scenarios
*/
int sfpstack_init( SF_PSTACK * s, void ** a,  int n  )
{
   s->imalloc=0;
   if( a ) s->stack = a;
   else
   {
      s->stack = (void**) malloc( n * sizeof(void*) );
      s->imalloc=1;
   }

   if( !s->stack ) return -1;
   s->nstack= n;
   s->n =0;
   return 0;
}
int sfpstack_push( SF_PSTACK *s, void * value)
{
   if( s->n < s->nstack )
   {
       s->stack[s->n++] = value;
       return 0;
   }
   return -1;
}
int sfpstack_pop( SF_PSTACK *s, void ** value)
{
   if( s->n > 0 )
   {
       s->n--;
       *value = s->stack[s->n];
       return 0;
   }
   return -1;
}

