/*
** bnfa_search.c   
**
** Basic multi-pattern search engine using Aho-Corasick NFA construction.
**
** Version 3.0  (based on acsmx.c and acsmx2.c)
**
** author: marc norton
** date:   started 12/21/05
**
** Copyright(C) 2005-2006 Sourcefire, Inc.
** 
** General Design
**   Aho-Corasick based NFA state machine. 
**   Compacted sparse storage mode for better performance.
**   Up to 16 Million states + transitions (combined) in compacted sparse mode.
**
**   ** Compacted sparse array storage **  
**
**   The primary data is held in one array.
**   The patterns themselves are stored separately.
**   The matching lists of patterns for each state are stored separately as well.
**   The compacted sparse format improves caching/performance.
**
**     word 1 : state  ( only low 24 bits are used )
**     word 2 : control word = cb << 24 | fs
**		cb: control byte 
**			cb = mb | fb | nt
**          mb : 8th bit - if set state has matching patterns bit
**		    fb : 7th bit - if set full storage array bit (256 entries used), else sparse
**		    nt : 0-63= number of transitions (more than 63 requires full storage)
**		fs: 24 bits for failure state transition index.
**	   word 3+ : transition word =  input<<24 |  next-state-index
**		input				: 8 bit character, input to state machine from search text
**		next-state-index	: 24 bits for index of next state
**		(if we reallly need  16M states, we can add a state->index lookup array)
**	  ...repeat for each state ...
**
**    * if a state is empty it has words 1 and 2, but no transition words.
**    
**   Construction:
**
**   Patterns are added to a list based trie.
**   The list based trie is compiled into a list based NFA with failure states.
**   The list based NFA is converted to full or sparse format NFA. 
**   The Zero'th state sparse transitions may be stored in full format for performance.
**   Sparse transition arrays are searched using linear and binary search strategies
**   depending on the number of entries to search through in each state.
**   The state machine in sparse mode is compacted into a single vector for 
*    better performance.
**   
** Notes:
**   
**   The NFA can require twice the state transitions that a DFA uses. However,
** the construction of a DFA generates many additional transitions in each
** state which consumes significant additional memory. This particular 
** implementation is best suited to environments where the very large memory 
** requirements of a full state table implementation is not possible and/or 
** the speed trade off is warranted to maintain a small memory footprint.
**
** Each state of an NFA usually has very few transitions but can have up to 256.
** It is important to not degenerate into a linear search so we utilize a binary
** search if there are more than 5 elements in the state to test for a match.
** This allows us to use a simple sparse memory design with an acceptable worst case
** search scenario.  The binary search over 256 elements is limtied to a max of
** 8 tests.  The zero'th state may use a full 256 state array, so a quick index lookup
** provides the next state transition.  The zero'th state is generally visited much
** more than other states.
**
** Compiling : gcc, Intel C/C++, Microsoft C/C++, each optimize differently. My studies
** have shown Intel C/C++ 9,8,7 to be the fastest, Microsoft 8,7,6 is next fastest,
** and gcc 4.x,3.x,2.x is the slowest of the three.  My testing has been mainly on x86.
** In general gcc does a poor job with optimizing this state machine for performance, 
** compared to other less cache and prefetch sensitive algorithms.  I've documented
** this behavior in a paper 'Optimizing Pattern Matching for IDS' (www.sourcefire.com,
** www.idsresearch.org).
**
** The code is sensitive to cache optimization and prefetching, as well as instruction 
** pipelining.  Aren't we all.  To this end, the number of patterns, length of search text,
** and cpu cache L1,L2,L3 all affect performance. The relative performance of the sparse
** and full format NFA and DFA varies as you vary the pattern charactersitics,and search
** text length, but strong performance trends are present and stable.
**
**
**  BNFA API SUMMARY
**
**  bnfa=bnfaNew();				create a state machine
**  bnfaAddPattern(bnfa,..);	add a pattern to the state machine
**  bnfaCompile (bnfa,..)		compile the state machine
**  bnfaPrintInfo(bnfa);		print memory usage and state info
**  bnfaPrint(bnfa);			print the state machine in total 
**  state=bnfaSearch(bnfa, ...,state);	search a data buffer for a pattern match
**  bnfaFree (bnfa);			free the bnfa
**
**
** Reference - Efficient String matching: An Aid to Bibliographic Search
**             Alfred V Aho and Margaret J Corasick
**             Bell Labratories 
**             Copyright(C) 1975 Association for Computing Machinery,Inc
**
** LICENSE (GPL)
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/  
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
  
#include "bnfa_search.h"


/*
* Case Translation Table - his guarantees we use 
* indexed lookups for case conversion
*/ 
static 
unsigned char xlatcase[BNFA_MAX_ALPHABET_SIZE];
static
void init_xlatcase() 
{
  int i;
  static int first=1;

  if( !first ) 
	  return;

  for(i=0; i<BNFA_MAX_ALPHABET_SIZE; i++)
  {
      xlatcase[i] = (unsigned char)toupper(i);
  }

  first=0;
}

/*
* Custom memory allocator
*/ 
void * bnfa_malloc( int n, int * m )
{
   void * p = calloc(1,n);
   if( p )
   {
     if(m)
	 {
		 m[0] += n;
	 }
   }
   return p;
}
void bnfa_free( void *p, int n, int * m )
{
   if( p )
   {
	   free(p);
	   if(m)
	   {
	         m[0] -= n;
	   }
   }
}
#define BNFA_MALLOC(n,memory) bnfa_malloc(n,&(memory))
#define BNFA_FREE(p,n,memory) bnfa_free(p,n,&(memory))


/* queue memory traker */
static int queue_memory=0;

/*
*    simple queue node
*/ 
typedef struct _qnode
{
   unsigned state;
   struct _qnode *next;
}
QNODE;
/*
*    simple fifo queue structure
*/ 
typedef struct _queue
{
  QNODE * head, *tail;
  int count;
  int maxcnt;
}
QUEUE;
/*
*   Initialize the fifo queue
*/ 
static
void queue_init (QUEUE * s) 
{
  s->head = s->tail = 0;
  s->count= 0;
  s->maxcnt=0;
}
/*
*  Add items to tail of queue (fifo)
*/ 
static
int queue_add (QUEUE * s, int state) 
{
  QNODE * q;
  if (!s->head)
  {
      q = s->tail = s->head = (QNODE *) BNFA_MALLOC (sizeof(QNODE),queue_memory);
      if(!q) return -1;
      q->state = state;
      q->next = 0;
  }
  else
  {
      q = (QNODE *) BNFA_MALLOC (sizeof(QNODE),queue_memory);
      q->state = state;
      q->next = 0;
      s->tail->next = q;
      s->tail = q;
  }
  s->count++;
  
  if( s->count > s->maxcnt )
	  s->maxcnt = s->count;

  return 0;
}
/*
*  Remove items from head of queue (fifo)
*/ 
static 
int queue_remove (QUEUE * s) 
{
  int state = 0;
  QNODE * q;
  if (s->head)
  {
      q       = s->head;
      state   = q->state;
      s->head = s->head->next;
      s->count--;

      if( !s->head )
      {
	    s->tail = 0;
	    s->count = 0;
      }
      BNFA_FREE (q,sizeof(QNODE),queue_memory);
  }
  return state;
}
/*
*   Return count of items in the queue
*/ 
static 
int queue_count (QUEUE * s) 
{
  return s->count;
}
/*
*  Free the queue
*/ 
static
void queue_free (QUEUE * s) 
{
  while (queue_count (s))
    {
      queue_remove (s);
    }
}

/*
*  Get next state from transition list
*/
static 
int _bnfa_list_get_next_state( bnfa_struct_t * bnfa, int state, int input )
{
  if ( state == 0 ) /* Full set of states  always */
  {
       bnfa_state_t * p = (bnfa_state_t*)bnfa->bnfaTransTable[0];
       if(!p) 
	   {
		   return 0;
	   }
       return p[input];
  }
  else
  {
    bnfa_trans_node_t * t = bnfa->bnfaTransTable[state];
    while( t )
    {
      if( t->key == (unsigned)input )
      {
        return t->next_state;
      }
      t=t->next;
    }
    return BNFA_FAIL_STATE; /* Fail state */
  }
}

/*
*  Put next state - head insertion, and transition updates
*/
static 
int _bnfa_list_put_next_state( bnfa_struct_t * bnfa, int state, int input, int next_state )
{
  if( state >= bnfa->bnfaMaxStates )
  {
	  return -1;
  }

  if( input >= bnfa->bnfaAlphabetSize )
  {
	  return -1;
  }

  if( state == 0 )
  {
    bnfa_state_t * p; 

    p = (bnfa_state_t*)bnfa->bnfaTransTable[0];
    if( !p )
    {
       p = (bnfa_state_t*)BNFA_MALLOC(sizeof(bnfa_state_t)*bnfa->bnfaAlphabetSize,bnfa->list_memory);
       if( !p ) 
	   {
		   return -1; 
	   }

       bnfa->bnfaTransTable[0] = (bnfa_trans_node_t*)p;
    }
    if( p[input] )
    {
        p[input] =  next_state;
        return 0;
    }
    p[input] =  next_state;
  }
  else
  {
    bnfa_trans_node_t * p;
    bnfa_trans_node_t * tnew;

    /* Check if the transition already exists, if so just update the next_state */
    p = bnfa->bnfaTransTable[state];
    while( p )
    {
      if( p->key == (unsigned)input )  /* transition already exists- reset the next state */
      {
          p->next_state = next_state;
          return 0; 
      }
      p=p->next;
    }

    /* Definitely not an existing transition - add it */
    tnew = (bnfa_trans_node_t*)BNFA_MALLOC(sizeof(bnfa_trans_node_t),bnfa->list_memory);
    if( !tnew )
	{
	  return -1; 
	}

    tnew->key        = input;
    tnew->next_state = next_state;
    tnew->next       = bnfa->bnfaTransTable[state];

    bnfa->bnfaTransTable[state] = tnew; 
  }

  bnfa->bnfaNumTrans++;

  return 0; 
}

/*
*   Free the entire transition list table 
*/
static 
int _bnfa_list_free_table( bnfa_struct_t * bnfa )
{
  int i;
  bnfa_trans_node_t * t, *p;

  if( !bnfa->bnfaTransTable ) return 0;

  if( bnfa->bnfaTransTable[0] )
  {
      BNFA_FREE(bnfa->bnfaTransTable[0],sizeof(bnfa_state_t)*bnfa->bnfaAlphabetSize,bnfa->list_memory);
  }

  for(i=1; i<bnfa->bnfaMaxStates; i++)
  {  
     t = bnfa->bnfaTransTable[i];

     while( t )
     {
       p = t;
       t = t->next;
       BNFA_FREE(p,sizeof(bnfa_trans_node_t),bnfa->list_memory);      
     }
   }

   if( bnfa->bnfaTransTable )
   {
      BNFA_FREE(bnfa->bnfaTransTable,sizeof(bnfa_trans_node_t*)*bnfa->bnfaMaxStates,bnfa->list_memory);
      bnfa->bnfaTransTable = 0;
   }

   return 0;
}

#ifdef ALLOW_LIST_PRINT
/*
* Print the transition list table to stdout
*/
static 
int _bnfa_list_print_table( bnfa_struct_t * bnfa )
{
  int i;
  bnfa_trans_node_t * t;
  bnfa_match_node_t * mn;
  bnfa_pattern_t * patrn;

  if( !bnfa->bnfaTransTable )
  {
      return 0;
  }

  printf("Print Transition Table- %d active states\n",bnfa->bnfaNumStates);

  for(i=0;i< bnfa->bnfaNumStates;i++)
  {  
     printf("state %3d: ",i);

     if( i == 0 )
     {
		int k;
        bnfa_state_t * p = (bnfa_state_t*)bnfa->bnfaTransTable[0];
        if(!p) continue;

        for(k=0;k<bnfa->bnfaAlphabetSize;k++)
        {
          if( p[k] == 0 ) continue;

          if( isprint(p[k]) )
             printf("%3c->%-5d\t",k,p[k]);
          else
             printf("%3d->%-5d\t",k,p[k]);
        }
     }
     else
     {
       t = bnfa->bnfaTransTable[i];
       while( t )
       { 
         if( isprint(t->key) )
           printf("%3c->%-5d\t",t->key,t->next_state);
         else
           printf("%3d->%-5d\t",t->key,t->next_state);
         t = t->next;
       }
     }

     mn =bnfa->bnfaMatchList[i];
     while( mn )
     {
	   patrn =(bnfa_pattern_t *)mn->data;
       printf("%.*s ",patrn->n,patrn->casepatrn);
       mn = mn->next;
     }
     printf("\n");
   }
   return 0;
}
#endif
/*
* Converts a single row of states from list format to a full format
*/ 
static 
int _bnfa_list_conv_row_to_full(bnfa_struct_t * bnfa, bnfa_state_t state, bnfa_state_t * full )
{
    if( (int)state >= bnfa->bnfaMaxStates ) /* protects 'full' against overflow */
    {
	return -1;
    }

    if( state == 0 )
    {
       if( bnfa->bnfaTransTable[0] )
          memcpy(full,bnfa->bnfaTransTable[0],sizeof(bnfa_state_t)*bnfa->bnfaAlphabetSize);
       else
          memset(full,0,sizeof(bnfa_state_t)*bnfa->bnfaAlphabetSize);

       return bnfa->bnfaAlphabetSize;
    }
    else
    {
       int tcnt = 0;
 
       bnfa_trans_node_t * t = bnfa->bnfaTransTable[ state ];

       memset(full,0,sizeof(bnfa_state_t)*bnfa->bnfaAlphabetSize);
   
       if( !t )
	   {
		   return 0;
	   }

       while(t && (t->key < BNFA_MAX_ALPHABET_SIZE ) )
       {
         full[ t->key ] = t->next_state;
         tcnt++;
         t = t->next;
       }
       return tcnt;
    }
}

/*
*  Add pattern characters to the initial upper case trie
*/
static 
int _bnfa_add_pattern_states (bnfa_struct_t * bnfa, bnfa_pattern_t * p) 
{
  int             state, next, n;
  unsigned char * pattern;
  bnfa_match_node_t  * pmn;

  n       = p->n;
  pattern = p->casepatrn;
  state   = 0;

  /* 
  *  Match up pattern with existing states
  */ 
  for (; n > 0; pattern++, n--)
  {
      next = _bnfa_list_get_next_state(bnfa,state,xlatcase[*pattern]);

      if( next == BNFA_FAIL_STATE || next == 0 )
      {
         break;
      }
      state = next;
  }
  
  /*
  *   Add new states for the rest of the pattern bytes, 1 state per byte, uppercase
  */ 
  for (; n > 0; pattern++, n--)
  {
      bnfa->bnfaNumStates++; 

      if( _bnfa_list_put_next_state(bnfa,state,xlatcase[*pattern],bnfa->bnfaNumStates)  < 0 )
          return -1;

      state = bnfa->bnfaNumStates;

      if ( bnfa->bnfaNumStates >= bnfa->bnfaMaxStates )
      {
	       return -1;
      }
  }

  /*  Add a pattern to the list of patterns terminated at this state */
  pmn = (bnfa_match_node_t*)BNFA_MALLOC(sizeof(bnfa_match_node_t),bnfa->matchlist_memory);
  if( !pmn )
  {
	  return -1;
  }

  pmn->data = p;
  pmn->next = bnfa->bnfaMatchList[state];

  bnfa->bnfaMatchList[state] = pmn;

  return 0;
}


/*
*   Build a non-deterministic finite automata using Aho-Corasick construction
*   The keyword trie must already be built via _bnfa_add_pattern_states()
*/ 
static 
int _bnfa_build_nfa (bnfa_struct_t * bnfa) 
{
    int             r, s, i;
    QUEUE           q, *queue = &q;
    bnfa_state_t     * FailState = bnfa->bnfaFailState;
    bnfa_match_node_t ** MatchList = bnfa->bnfaMatchList;
    bnfa_match_node_t  * mlist;
    bnfa_match_node_t  * px;
  
	/* Init a Queue */ 
	queue_init (queue);
  
	/* Add the state 0 transitions 1st, 
	* the states at depth 1, fail to state 0 
	*/ 
	for (i = 0; i < bnfa->bnfaAlphabetSize; i++)
	{
		/* note that state zero deos not fail, 
		*  it just returns 0..nstates-1 
		*/
		s = _bnfa_list_get_next_state(bnfa,0,i); 
		if( s ) /* don't bother adding state zero */
		{
		  if( queue_add (queue, s) ) 
		  {
              return -1;
		  }
		  FailState[s] = 0;
		}
	}
  
	/* Build the fail state successive layer of transitions */
	while (queue_count (queue) > 0)
	{
		r = queue_remove (queue);
      
		/* Find Final States for any Failure */ 
		for(i = 0; i<bnfa->bnfaAlphabetSize; i++)
		{
			int fs, next;

			s = _bnfa_list_get_next_state(bnfa,r,i);

			if( s == BNFA_FAIL_STATE )
				continue;
		   
			if( queue_add (queue, s) ) 
			{
				return -1;
			}
 
			fs = FailState[r];

			/* 
			*  Locate the next valid state for 'i' starting at fs 
			*/ 
			while( (next=_bnfa_list_get_next_state(bnfa,fs,i)) == BNFA_FAIL_STATE )
			{
				fs = FailState[fs];
			}
	      
			/*
			*  Update 's' state failure state to point to the next valid state
			*/ 
			FailState[s] = next;
	      
			/*
			*  Copy 'next'states MatchList into 's' states MatchList, 
			*  we just create a new list nodes, the patterns are not copied.
			*/ 
			for( mlist = MatchList[next];mlist;mlist = mlist->next)
			{
				/* Dup the node, don't copy the data */
				px = (bnfa_match_node_t*)BNFA_MALLOC(sizeof(bnfa_match_node_t),bnfa->matchlist_memory);
				if( !px )
				{
					return 0;
				}

				px->data = mlist->data; 
		  
				px->next = MatchList[s]; /* insert at head */
		 
				MatchList[s] = px;
			}
		}
	}
  
	/* Clean up the queue */
	queue_free (queue);

	return 0;
}

#ifdef ALLOW_NFA_FULL
/*
*  Conver state machine to full format
*/
static 
int _bnfa_conv_list_to_full(bnfa_struct_t * bnfa) 
{
  int          k;
  bnfa_state_t  * p;
  bnfa_state_t ** NextState = bnfa->bnfaNextState;

  for(k=0;k<bnfa->bnfaNumStates;k++)
  {
    p = BNFA_MALLOC(sizeof(bnfa_state_t)*bnfa->bnfaAlphabetSize,bnfa->nextstate_memory);
    if(!p)
    {
      return -1;
    }
    _bnfa_list_conv_row_to_full( bnfa, (bnfa_state_t)k, p );

    NextState[k] = p; /* now we have a full format row vector */
  }

  return 0;
}
#endif

/*
*  Convert state machine to csparse format
*
*  Merges state/transition/failure arrays into one.
*
*  For each state we use a state-word followed by the transition list for the state
*  sw(state 0 )...tl(state 0) sw(state 1)...tl(state1) sw(state2)...tl(state2) ....
*  
*  The transition and failure states are replaced with the start index of transition state,
*  this eliminates the NextState[] lookup....
*
*  The compaction of multiple arays into a single array reduces the total number of
*  states that can be handled since the max index is 2^24-1, whereas without compaction
*  we had 2^24-1 states.  
*/
static 
int _bnfa_conv_list_to_csparse_array(bnfa_struct_t * bnfa) 
{
  int            m, k, i, nc;
  bnfa_state_t      state;
  bnfa_state_t    * FailState = (bnfa_state_t  *)bnfa->bnfaFailState;
  bnfa_state_t    * ps; /* transition list */
  bnfa_state_t    * pi; /* state indexes into ps */
  bnfa_state_t      ps_index=0;
  unsigned       nps;
  bnfa_state_t      full[BNFA_MAX_ALPHABET_SIZE];

  
  /* count total state transitions, account for state and control words  */
  nps = 0;
  for(k=0;k<bnfa->bnfaNumStates;k++)
  {
	nps++; /* state word */
	nps++; /* control word */

	/* count transitions */
	nc = 0;
	_bnfa_list_conv_row_to_full(bnfa, (bnfa_state_t)k, full );
	for( i=0; i<bnfa->bnfaAlphabetSize; i++ )
	{
		state = full[i] & BNFA_SPARSE_MAX_STATE;
		if( state != 0 )
		{
			nc++;
		}	
	}

	/* add in transition count */
   	if( (k == 0 && bnfa->bnfaForceFullZeroState) || nc > BNFA_SPARSE_MAX_ROW_TRANSITIONS )
	{
		nps += BNFA_MAX_ALPHABET_SIZE;
	}
	else
	{
   	    for( i=0; i<bnfa->bnfaAlphabetSize; i++ )
		{
		   state = full[i] & BNFA_SPARSE_MAX_STATE;
		   if( state != 0 )
		   {
		       nps++;
		   }	
		}
	}
  }

  /* check if we have too many states + transitions */
  if( nps > BNFA_SPARSE_MAX_STATE )
  {
	  /* Fatal */
	  return -1;
  }

  /*
    Alloc The Transition List - we need an array of bnfa_state_t items of size 'nps'
  */
  ps = BNFA_MALLOC( nps*sizeof(bnfa_state_t),bnfa->nextstate_memory);
  if( !ps ) 
  {
	  /* Fatal */
	  return -1;
  }
  bnfa->bnfaTransList = ps;
  
  /* 
     State Index list for pi - we need an array of bnfa_state_t items of size 'NumStates' 
  */
  pi = BNFA_MALLOC( bnfa->bnfaNumStates*sizeof(bnfa_state_t),bnfa->nextstate_memory);
  if( !pi ) 
  {
	  /* Fatal */
	  return -1;
  }

  /* 
      Build the Transition List Array
  */
  for(k=0;k<bnfa->bnfaNumStates;k++)
  {
	pi[k] = ps_index; /* save index of start of state 'k' */

	ps[ ps_index ] = k; /* save the state were in as the 1st word */
	
	ps_index++;  /* skip past state word */

	/* conver state 'k' to full format */
	_bnfa_list_conv_row_to_full(bnfa, (bnfa_state_t)k, full );

	/* count transitions */
	nc = 0;
	for( i=0; i<bnfa->bnfaAlphabetSize; i++ )
	{
		state = full[i] & BNFA_SPARSE_MAX_STATE;
		if( state != 0 )
		{
			nc++;
		}	
	}

	/* add a full state or a sparse state  */
	if( (k == 0 && bnfa->bnfaForceFullZeroState) || 
		nc > BNFA_SPARSE_MAX_ROW_TRANSITIONS )
	{
		/* set the control word */
		ps[ps_index]  = BNFA_SPARSE_FULL_BIT;
		ps[ps_index] |= FailState[k] & BNFA_SPARSE_MAX_STATE;
		if( bnfa->bnfaMatchList[k] )
		{
            ps[ps_index] |= BNFA_SPARSE_MATCH_BIT;
		}
		ps_index++;  

		/* copy the transitions */
		_bnfa_list_conv_row_to_full(bnfa, (bnfa_state_t)k, &ps[ps_index] );

 		ps_index += BNFA_MAX_ALPHABET_SIZE;  /* add in 256 transitions */

	}
   	else
	{
		/* set the control word */
   		ps[ps_index]  = nc<<BNFA_SPARSE_COUNT_SHIFT ;
   		ps[ps_index] |= FailState[k]&BNFA_SPARSE_MAX_STATE;
   		if( bnfa->bnfaMatchList[k] )
	  	{
       		ps[ps_index] |= BNFA_SPARSE_MATCH_BIT;
	  	}
		ps_index++;

		/* add in the transitions */
   		for( m=0, i=0; i<bnfa->bnfaAlphabetSize && m<nc; i++ )
	  	{
       		state = full[i] & BNFA_SPARSE_MAX_STATE;
       		if( state != 0 )
		 	{
           		ps[ps_index++] = (i<<BNFA_SPARSE_VALUE_SHIFT) | state;
				m++;
		 	}
	  	}
	}
  }

  /* sanity check we have not overflowed our buffer */
  if( ps_index > nps ) 
  {
	  /* Fatal */
	  return -1;
  }

  /* 
  Replace Transition states with Transition Indices. 
  This allows us to skip using NextState[] to locate the next state
  This limits us to <16M transitions due to 24 bit state sizes, and the fact
  we have now converted next-state fields to next-index fields in this array,
  and we have merged the next-state and state arrays.
  */
  ps_index=0;
  for(k=0; k< bnfa->bnfaNumStates; k++ )
  {
	 if( pi[k] >= nps )
	 {
		 /* Fatal */
		 return -1;
	 }

	 //ps_index = pi[k];  /* get index of next state */
	 ps_index++;        /* skip state id */

	 /* Full Format */
     if( ps[ps_index] & BNFA_SPARSE_FULL_BIT )
	 {
	   /* Do the fail-state */
       ps[ps_index] = ( ps[ps_index] & 0xff000000 ) | 
		              ( pi[ ps[ps_index] & BNFA_SPARSE_MAX_STATE ] ) ; 
	   ps_index++;

	   /* Do the transition-states */
	   for(i=0;i<BNFA_MAX_ALPHABET_SIZE;i++)
	   {
		 ps[ps_index] = ( ps[ps_index] & 0xff000000 ) | 
		                ( pi[ ps[ps_index] & BNFA_SPARSE_MAX_STATE ] ) ; 
		 ps_index++;
	   }
	 }

	 /* Sparse Format */
	 else
	 {
       	nc = (ps[ps_index] & BNFA_SPARSE_COUNT_BITS)>>BNFA_SPARSE_COUNT_SHIFT;
	   
	   	/* Do the cw = [cb | fail-state] */
   		ps[ps_index] =  ( ps[ps_index] & 0xff000000 ) |
						( pi[ ps[ps_index] & BNFA_SPARSE_MAX_STATE ] ); 
	   	ps_index++;

	   	/* Do the transition-states */
	   	for(i=0;i<nc;i++)
	   	{
       		ps[ps_index] = ( ps[ps_index] & 0xff000000 ) |
			               ( pi[ ps[ps_index] & BNFA_SPARSE_MAX_STATE ] );
		 	ps_index++;
	   	}
	 }

	 /* check for buffer overflow again */
 	 if( ps_index > nps )
	 {
		 /* Fatal */
		 return -1;
	 }

  }

  BNFA_FREE(pi,bnfa->bnfaNumStates*sizeof(bnfa_state_t),bnfa->nextstate_memory);

  return 0;
}

/*
*  Print the state machine - rather verbose
*/
void bnfaPrint(bnfa_struct_t * bnfa) 
{
  int			   k;
  bnfa_match_node_t  ** MatchList = bnfa->bnfaMatchList;
  bnfa_match_node_t   * mlist;
  int              ps_index=0;
  bnfa_state_t      * ps=0;

  if( !bnfa ) 
      return;
  
  if( !bnfa->bnfaNumStates ) 
	  return;

  if( bnfa->bnfaFormat ==BNFA_SPARSE )
  {
    printf("Print NFA-SPARSE state machine : %d active states\n", bnfa->bnfaNumStates);
    ps = bnfa->bnfaTransList;
    if( !ps )
        return;
  }

#ifdef ALLOW_NFA_FULL
  else if( bnfa->bnfaFormat ==BNFA_FULL )
  {
    printf("Print NFA-FULL state machine : %d active states\n", bnfa->bnfaNumStates);
  }
#endif
  
  
  for(k=0;k<bnfa->bnfaNumStates;k++)
  {
    printf(" state %-4d fmt=%d ",k,bnfa->bnfaFormat);

    if( bnfa->bnfaFormat == BNFA_SPARSE )
    {
	   unsigned i,cw,fs,nt,fb,mb;
       
	   ps_index++; /* skip state number */

       cw = ps[ps_index]; /* control word  */
	   fb = (cw &  BNFA_SPARSE_FULL_BIT)>>BNFA_SPARSE_VALUE_SHIFT;  /* full storage bit */ 
	   mb = (cw &  BNFA_SPARSE_MATCH_BIT)>>BNFA_SPARSE_VALUE_SHIFT; /* matching state bit */
	   nt = (cw &  BNFA_SPARSE_COUNT_BITS)>>BNFA_SPARSE_VALUE_SHIFT;/* number of transitions 0-63 */
	   fs = (cw &  BNFA_SPARSE_MAX_STATE)>>BNFA_SPARSE_VALUE_SHIFT; /* fail state */

	   ps_index++;  /* skip control word */

	   printf("mb=%3u fb=%3u fs=%-4u ",mb,fb,fs);

	   if( fb )
       {
         printf(" nt=%-3d : ",bnfa->bnfaAlphabetSize);

         for( i=0; i<(unsigned)bnfa->bnfaAlphabetSize; i++, ps_index++  )
         { 
    	    if( ps[ps_index] == 0  ) continue;

            if( isprint(i) )
               printf("%3c->%-6d\t",i,ps[ps_index]);
            else
               printf("%3d->%-6d\t",i,ps[ps_index]);
         }
       }  
       else
       {
          printf(" nt=%-3d : ",nt);

          for( i=0; i<nt; i++, ps_index++ )
          { 
             if( isprint(ps[ps_index]>>BNFA_SPARSE_VALUE_SHIFT) )
               printf("%3c->%-6d\t",ps[ps_index]>>BNFA_SPARSE_VALUE_SHIFT,ps[ps_index] & BNFA_SPARSE_MAX_STATE);
             else
			   printf("%3d->%-6d\t",ps[ps_index]>>BNFA_SPARSE_VALUE_SHIFT,ps[ps_index] & BNFA_SPARSE_MAX_STATE);
          }
       }
    }
#ifdef ALLOW_NFA_FULL
    else if( bnfa->bnfaFormat == BNFA_FULL ) 
    {
       int          i;
       bnfa_state_t    state;
       bnfa_state_t  * p;   
       bnfa_state_t ** NextState;

       NextState = (bnfa_state_t **)bnfa->bnfaNextState;
       if( !NextState ) 
		   continue;

       p = NextState[k];

       printf("fs=%-4d nc=256 ",bnfa->bnfaFailState[k]);

       for( i=0; i<bnfa->bnfaAlphabetSize; i++ )
       {
          state = p[i];

          if( state != 0 && state != BNFA_FAIL_STATE )
          {
             if( isprint(i) )
               printf("%3c->%-5d\t",i,state);
             else
               printf("%3d->%-5d\t",i,state);
          }
       }
    }
#endif

   printf("\n");

   if( MatchList[k] )
       printf("---MatchList For State %d\n",k);

    for( mlist = MatchList[k];
         mlist!= NULL;
         mlist = mlist->next )
    {
	     bnfa_pattern_t * pat;
		 pat = (bnfa_pattern_t*)mlist->data;
         printf("---pattern : %.*s\n",pat->n,pat->casepatrn);
    }
  }
}

/*
*  Create a new AC state machine
*/ 
bnfa_struct_t * bnfaNew() 
{
  bnfa_struct_t * p;
  static int first=1;
  int bnfa_memory=0;

  if( first )
  {
      bnfaInitSummary();
      first=0;
  }
  
  init_xlatcase ();

  p = (bnfa_struct_t *) BNFA_MALLOC(sizeof(bnfa_struct_t),bnfa_memory);
  if(!p) 
	  return 0;

  if( p )
  {
     p->bnfaFormat             = BNFA_SPARSE;
     p->bnfaAlphabetSize       = BNFA_MAX_ALPHABET_SIZE;
     p->bnfaForceFullZeroState = 1;
     p->bnfa_memory            = sizeof(bnfa_struct_t);
  }
  
  queue_memory=0;
  return p;
}


/*
*   Fee all memory 
*/ 
void bnfaFree (bnfa_struct_t * bnfa) 
{
  int i;
  bnfa_pattern_t * patrn, *ipatrn;
  bnfa_match_node_t   * mlist, *ilist;

  for(i = 0; i < bnfa->bnfaNumStates; i++)
  {
      /* free match list entries */
      mlist = bnfa->bnfaMatchList[i];
      while (mlist)
      {
		ilist = mlist;
		mlist = mlist->next;
		BNFA_FREE(ilist,sizeof(bnfa_match_node_t),bnfa->matchlist_memory);
      }
      bnfa->bnfaMatchList[i] = 0;

#ifdef ALLOW_NFA_FULL
      /* free next state entries */
      if( bnfa->bnfaFormat==BNFA_FULL )/* Full format */
      {
         if( bnfa->bnfaNextState[i] )
		 {
            BNFA_FREE(bnfa->bnfaNextState[i],bnfa->bnfaAlphabetSize*sizeof(bnfa_state_t),bnfa->nextstate_memory);
		 }
      }
#endif
  }

  /* Free patterns */
  patrn = bnfa->bnfaPatterns;
  while(patrn)
  {
     ipatrn=patrn;
     patrn=patrn->next;
     BNFA_FREE(ipatrn->casepatrn,ipatrn->n,bnfa->pat_memory);
     BNFA_FREE(ipatrn,sizeof(bnfa_pattern_t),bnfa->pat_memory);
  }

  /* Free arrays */
  BNFA_FREE(bnfa->bnfaFailState,bnfa->bnfaNumStates*sizeof(bnfa_state_t),bnfa->failstate_memory);
  BNFA_FREE(bnfa->bnfaMatchList,bnfa->bnfaNumStates*sizeof(bnfa_pattern_t*),bnfa->matchlist_memory);
  BNFA_FREE(bnfa->bnfaNextState,bnfa->bnfaNumStates*sizeof(bnfa_state_t*),bnfa->nextstate_memory);
  BNFA_FREE(bnfa->bnfaTransList,(2*bnfa->bnfaNumStates+bnfa->bnfaNumTrans)*sizeof(bnfa_state_t*),bnfa->nextstate_memory);
  free( bnfa ); /* cannot update memory tracker when deleting bnfa so just 'free' it !*/
}

/*
*   Add a pattern to the pattern list
*/ 
int
bnfaAddPattern (bnfa_struct_t * p, 
				unsigned char *pat, int n, int nocase,
				void * userdata )
{
  bnfa_pattern_t * plist;

  plist = (bnfa_pattern_t *)BNFA_MALLOC(sizeof(bnfa_pattern_t),p->pat_memory);
  if(!plist) return -1;

  plist->casepatrn = (unsigned char *)BNFA_MALLOC(n,p->pat_memory );
  if(!plist->casepatrn) return -1;
  
  memcpy (plist->casepatrn, pat, n);

  plist->n        = n;
  plist->nocase   = nocase;
  plist->userdata = userdata;

  plist->next     = p->bnfaPatterns; /* insert at front of list */
  p->bnfaPatterns = plist;

  p->bnfaPatternCnt++;

  return 0;
}

/*
*   Compile the patterns into an nfa state machine 
*/ 
int
bnfaCompile (bnfa_struct_t * bnfa) 
{
    bnfa_pattern_t  * plist;
    bnfa_match_node_t   ** tmpMatchList;
	unsigned          cntMatchStates;
	int               i;
    static int first=1;

    if( first )
    {
        bnfaInitSummary();
        first=0;
    }
	queue_memory =0;

    /* Count number of states */ 
    for(plist = bnfa->bnfaPatterns; plist != NULL; plist = plist->next)
    {
       bnfa->bnfaMaxStates += plist->n;
    }
    bnfa->bnfaMaxStates++; /* one extra */

    /* Alloc a List based State Transition table */
    bnfa->bnfaTransTable =(bnfa_trans_node_t**) BNFA_MALLOC(sizeof(bnfa_trans_node_t*) * bnfa->bnfaMaxStates,bnfa->list_memory );
    if(!bnfa->bnfaTransTable)
	{
		return -1;
	}

    /* Alloc a MatchList table - this has a list of pattern matches for each state */
    bnfa->bnfaMatchList=(bnfa_match_node_t**) BNFA_MALLOC(sizeof(void*)*bnfa->bnfaMaxStates,bnfa->matchlist_memory );
    if(!bnfa->bnfaMatchList)
	{
		return -1;
	}

    /* Add each Pattern to the State Table - This forms a keyword trie using lists */ 
    bnfa->bnfaNumStates = 0;
    for (plist = bnfa->bnfaPatterns; plist != NULL; plist = plist->next)
    {
        _bnfa_add_pattern_states (bnfa, plist);
    }
    bnfa->bnfaNumStates++;

    if( bnfa->bnfaNumStates > BNFA_SPARSE_MAX_STATE )
	{
		return -1;  /* Call bnfaFree to clean up */
	}

    /* ReAlloc a smaller MatchList table -  only need NumStates  */
    tmpMatchList=bnfa->bnfaMatchList;

    bnfa->bnfaMatchList=(bnfa_match_node_t**)BNFA_MALLOC(sizeof(void*) * bnfa->bnfaNumStates,bnfa->matchlist_memory);
    if(!bnfa->bnfaMatchList)
	{
		return -1;
	}
    
	memcpy(bnfa->bnfaMatchList,tmpMatchList,sizeof(void*) * bnfa->bnfaNumStates);
    
	BNFA_FREE(tmpMatchList,sizeof(void*) * bnfa->bnfaMaxStates,bnfa->matchlist_memory);

    /* Alloc a failure state table -  only need NumStates */
    bnfa->bnfaFailState =(bnfa_state_t*)BNFA_MALLOC(sizeof(bnfa_state_t) * bnfa->bnfaNumStates,bnfa->failstate_memory);
    if(!bnfa->bnfaFailState)
	{
		return -1;
	}

#ifdef ALLOW_NFA_FULL
    if( bnfa->bnfaFormat == BNFA_FULL )
	{
	  /* Alloc a state transition table -  only need NumStates  */
      bnfa->bnfaNextState=(bnfa_state_t**)BNFA_MALLOC(sizeof(bnfa_state_t*) * bnfa->bnfaNumStates,bnfa->nextstate_memory);
      if(!bnfa->bnfaNextState) 
	  {
		  return -1;
	  }
	}
#endif
	
    /* Build the nfa w/failure states - time the nfa construction */
    if( _bnfa_build_nfa (bnfa) ) 
	{
        return -1;
	}

    /* Convert nfa storage format from list to full or sparse */
    if( bnfa->bnfaFormat == BNFA_SPARSE )
    {
      if( _bnfa_conv_list_to_csparse_array(bnfa)  )
	  {
		  return -1;
	  }
      BNFA_FREE(bnfa->bnfaFailState,sizeof(bnfa_state_t)*bnfa->bnfaNumStates,bnfa->failstate_memory);
	  bnfa->bnfaFailState=0;
    }
#ifdef ALLOW_NFA_FULL
	else if( bnfa->bnfaFormat == BNFA_FULL )
    {
      if( _bnfa_conv_list_to_full( bnfa ) )
	  {
            return -1;
	  }
    }
#endif
	else
	{
		return -1;
	}

    /* Free up the Table Of Transition Lists */
    _bnfa_list_free_table( bnfa ); 

	/* Count states with Pattern Matches */
	cntMatchStates=0;
	for(i=0;i<bnfa->bnfaNumStates;i++)
	{
		if( bnfa->bnfaMatchList[i] )
			cntMatchStates++;
	}

	bnfa->bnfaMatchStates = cntMatchStates;
	bnfa->queue_memory    = queue_memory;

    bnfaAccumInfo( bnfa  );

    return 0;
}

#ifdef ALLOW_NFA_FULL

/*
*   Full Matrix Format Search
*/
static
inline
unsigned 
_bnfa_search_full_nfa(	bnfa_struct_t * bnfa, unsigned char *Tx, int n,
					int (*Match)(bnfa_pattern_t * id, int index, void *data), 
                    void *data, bnfa_state_t state ) 
{
  unsigned char   * Tend;
  unsigned char   * T;
  unsigned char     Tchar;
  unsigned long     index;
  bnfa_state_t      ** NextState= bnfa->bnfaNextState;
  bnfa_state_t       * FailState= bnfa->bnfaFailState;
  bnfa_match_node_t   ** MatchList= bnfa->bnfaMatchList;
  bnfa_state_t       * pc;
  bnfa_match_node_t    * mlist;
  bnfa_pattern_t  * patrn;

  T    = Tx;
  Tend = T + n;
 
  for( ; T < Tend; T++ )
  {
	Tchar = xlatcase[ *T ];

	for(;;)
	{
		pc = NextState[state];
		if( pc[Tchar] == 0 && state > 0 )
		{
			state = FailState[state];
		}
		else
		{
			state = pc[Tchar];
			break;
		}
	}

	if( state )
	{
    	for(	mlist = MatchList[state];
				mlist!= NULL;
				mlist = mlist->next )
    	{
		   		patrn = (bnfa_pattern_t*)mlist->data;
	
           		index = T - Tx - patrn->n + 1; 
       			if( patrn->nocase )
           		{
					if (Match (patrn, index, data))
						return state;
           		}
           		else
           		{
					if( memcmp (patrn->casepatrn, T - patrn->n + 1, patrn->n) == 0 )
					{
  						if (Match (patrn->userdata, index, data))
  							return state;
					}
           		}
    	}
	}
  }
  return state;
}
#endif

/*
   binary array search on sparse transition array

   O(logN) search times..same as a binary tree.
   data must be in sorted order in the array.

   return:  = -1 => not found
		   >= 0  => index of element 'val' 

  notes:
	val is tested against the high 8 bits of the 'a' array entry,
	this is particular to the storage format we are using.
*/
static
inline 
int _bnfa_binearch( bnfa_state_t * a, int a_len, int val )
{
   int m, l, r;
   int c;

   l = 0;
   r = a_len - 1;

   while( r >= l )
   {
      m = ( r + l ) >> 1;

	  c = a[m] >> BNFA_SPARSE_VALUE_SHIFT;

      if( val == c )
      {
          return m;
      }

      else if( val <  c )
      {
          r = m - 1;
      }

      else /* val > c */
      {
          l = m + 1; 
      }
   }
   return -1;
}

/*
*   Sparse format for state table using single array storage
*
*   word 1: state
*   word 2: control-word = cb<<24| fs
*           cb	: control-byte
*				: mb | fb | nt
*				mb : bit 8 set if match state, zero otherwise
*				fb : bit 7 set if using full format, zero otherwise
*				nt : number of transitions 0..63 (more than 63 requires full format)
*			fs: failure-transition-state 
*   word 3+: byte-value(0-255) << 24 | transition-state
*/
static
inline 
unsigned 
_bnfa_get_next_state_csparse_nfa(bnfa_state_t * pcx, unsigned sindex, unsigned  input)
{
   int k;
   int nc; 
   int index;
   register bnfa_state_t * pc;

    for(;;)
	{
      pc = pcx + sindex + 1; /* skip state-id == 1st word */

      if( pc[0] & BNFA_SPARSE_FULL_BIT )
	  {   
		if( sindex == 0 )
		{
		  return pc[1+input] & BNFA_SPARSE_MAX_STATE; 
		}
		else
		{
		  if( pc[1+input] & BNFA_SPARSE_MAX_STATE ) 
			  return pc[1+input] & BNFA_SPARSE_MAX_STATE;
		}
	  }
      else
	  {
         nc = (pc[0]>>BNFA_SPARSE_COUNT_SHIFT) & BNFA_SPARSE_MAX_ROW_TRANSITIONS;

	     if( nc > BNFA_SPARSE_LINEAR_SEARCH_LIMIT )
		 {
    	   /* binary search... */
		   index = _bnfa_binearch( pc+1, nc, input );
		   if( index >= 0 )
		   {
		      return pc[index+1] & BNFA_SPARSE_MAX_STATE;
		   }
		 }
	     else
		 {
    	   /* linear search... */
           for( k=0; k<nc; k++ ) 
		   {   
             if( (pc[k+1]>>BNFA_SPARSE_VALUE_SHIFT) == input )
			 {
                return pc[k+1] & BNFA_SPARSE_MAX_STATE;
			 }
		   }
		 }
	  }

	  /* no transition found ... get the failure state and try again  */
	  sindex = pc[0] & BNFA_SPARSE_MAX_STATE;
    } 

	return 0; // zero state 
}
static
inline
unsigned
_bnfa_search_csparse_nfa(   bnfa_struct_t * bnfa, unsigned char *Tx, int n,
		    			int (*Match)(bnfa_pattern_t * id, int index, void *data), 
						void *data, unsigned sindex ) 
{
  bnfa_match_node_t    * mlist;
  unsigned char   * Tend;
  unsigned char   * T;
  unsigned char     Tchar;
  unsigned          index;
  bnfa_match_node_t   ** MatchList = bnfa->bnfaMatchList;
  bnfa_pattern_t    * patrn;
  bnfa_state_t       * transList = bnfa->bnfaTransList;

  T    = Tx;
  Tend = T + n;
  
  for(; T<Tend; T++)
  {
   	Tchar = xlatcase[ *T ];

   	/* Transition to next state index */
   	sindex = _bnfa_get_next_state_csparse_nfa(transList,sindex,Tchar);

   	/* Log matches in this state - if any */
	if( sindex && (transList[sindex+1] & BNFA_SPARSE_MATCH_BIT) )
	{
       	for(mlist = MatchList[ transList[sindex] ];
			mlist!= NULL;
			mlist = mlist->next )
		{
		   	patrn = (bnfa_pattern_t*)mlist->data;

           	index = T - Tx - patrn->n + 1;
           	if( patrn->nocase )
           	{
	        	if (Match (patrn->userdata, index, data))
				  return sindex;
           	}
           	else
           	{  	/* If case sensitive pattern, do an exact match test */
			  	if( memcmp (patrn->casepatrn, T - patrn->n + 1, patrn->n) == 0 )
			  	{
  				  if (Match (patrn->userdata, index, data))
  					return sindex;
			  	}
           	}
		}
	  }
  }
  return sindex;
}


/*
*  BNFA Search Function
*
*  bnfa   - state machine
*  Tx     - text buffer to search
*  n      - number of bytes in Tx      
*  Match  - function to call when a match is found
*  data   - user supplied data that is passed to the Match function
*  sindex - state tracker, set value to zero to reset the state machine,
*			zero should be the value passed in on the 1st buffer or each buffer
*           that is to be analyzed on its own, the state machine updates this 
*			during searches. This allows for sequential buffer searchs without 
*			reseting the state machine. Save this value as returned from the 
*			previous search for the next search.
*
*  returns 
*	The state or sindex of the state machine. This can than be passed back
*   in on the next search, if desired.  
*/
unsigned 
bnfaSearch(	bnfa_struct_t * bnfa, unsigned char *Tx, int n,
			int (*Match) ( void * id, int index, void *data), 
            void *data, unsigned sindex )
{
   
#ifdef ALLOW_NFA_FULL

    if( bnfa->bnfaFormat == BNFA_SPARSE )
    {
      return _bnfa_search_csparse_nfa( bnfa, Tx, n, 
		  (int (*)(bnfa_pattern_t*,int i,void *data))Match, data, sindex );
    }
    else if( bnfa->bnfaFormat == BNFA_FULL )
    {
      return _bnfa_search_full_nfa( bnfa, Tx, n, 
		  (int (*)(bnfa_pattern_t *,int index, void *data) )Match,data, (bnfa_state_t) sindex );
    }

    return 0;

#else
	return _bnfa_search_csparse_nfa( bnfa, Tx, n, 
		(int (*)(bnfa_pattern_t *,int index,void *data) )Match, data, sindex );

#endif
}

/*
 *  Summary Info Data
 */
static bnfa_struct_t summary;
static int summary_cnt=0;

/*
*  Info: Print info a particular state machine.
*/
void bnfaPrintInfoEx( bnfa_struct_t * p, char * text )
{
    unsigned max_memory;

    if( !p->bnfaNumStates )
    {
	    return;
    }
    max_memory = p->bnfa_memory + p->pat_memory + p->list_memory + 
		         p->matchlist_memory + p->failstate_memory + p->nextstate_memory;

    if( text && summary_cnt )
    {
    printf("+-[AC-NFA Search Info%s]------------------------------\n",text);
   // printf("| Max States       : %uM\n", 16*summary_cnt);
    printf("| Instances        : %d\n",summary_cnt);
    }
    else
    {
    printf("+-[AC-NFA Search Info]------------------------------\n");
    //printf("| Max States       : 16M\n");
    }
    //printf("| Alphabet Size    : %d Chars\n",p->bnfaAlphabetSize);
    printf("| Patterns         : %d\n",p->bnfaPatternCnt);
    printf("| Pattern Chars    : %d\n",p->bnfaMaxStates);
    printf("| Num States       : %d\n",p->bnfaNumStates);
    // printf("| Num Transitions  : %d\n",p->bnfaNumTrans);
    printf("| Num Match States : %d\n",p->bnfaMatchStates);
    //printf("| State Density    : %.2f%%\n",100.0*(double)p->bnfaNumTrans/(p->bnfaNumStates*p->bnfaAlphabetSize));
    if( max_memory < 1024*1024 )
    {
       	printf("| Memory           :   %.2fKbytes\n", (float)max_memory/1024 );
	   	//printf("|   BNFA struct    :   %.2fK\n",(float)p->bnfa_memory/1024 );
		printf("|   Patterns       :   %.2fK\n",(float)p->pat_memory/1024 );
	    //printf("|   Trans Lists    :   %.2fK\n",(float)p->list_memory/1024 );
		printf("|   Match Lists    :   %.2fK\n",(float)p->matchlist_memory/1024 );
		printf("|   Next States    :   %.2fK\n",(float)p->nextstate_memory/1024 );
		//printf("|   Fail States    :   %.2fK\n",(float)p->failstate_memory/1024 );
    }
    else
    {
    	printf("| Memory           :   %.2fMbytes\n", (float)max_memory/(1024*1024) );
    	//printf("|   BNFA struct    :   %.2fM\n",(float)p->bnfa_memory/(1024*1024) );
	    printf("|   Patterns       :   %.2fM\n",(float)p->pat_memory/(1024*1024) );
	    //printf("|   Trans Lists    :   %.2fM\n",(float)p->list_memory/(1024*1024) );
    	printf("|   Match Lists    :   %.2fM\n",(float)p->matchlist_memory/(1024*1024) );
	    printf("|   Next States    :   %.2fM\n",(float)p->nextstate_memory/(1024*1024) );
	    //printf("|   Fail States    :   %.2fM\n",(float)p->failstate_memory/(1024*1024) );
    }
    printf("+-------------------------------------------------\n");
}
void bnfaPrintInfo( bnfa_struct_t * p )
{
     bnfaPrintInfoEx( p, 0 );
}

void bnfaPrintSummary( )
{
     bnfaPrintInfoEx( &summary, " Summary" );
}
void bnfaInitSummary()
{
    summary_cnt=0;
    memset(&summary,0,sizeof(bnfa_struct_t));
}
void bnfaAccumInfo( bnfa_struct_t * p )
{
    bnfa_struct_t * px = &summary;

    summary_cnt++;

    px->bnfaAlphabetSize  = p->bnfaAlphabetSize;
    px->bnfaPatternCnt   += p->bnfaPatternCnt;
    px->bnfaMaxStates    += p->bnfaMaxStates;
    px->bnfaNumStates    += p->bnfaNumStates;
    px->bnfaNumTrans     += p->bnfaNumTrans;
    px->bnfaMatchStates  += p->bnfaMatchStates;
	px->bnfa_memory      += p->bnfa_memory;
	px->pat_memory       += p->pat_memory;
	px->list_memory      += p->list_memory;
	px->matchlist_memory += p->matchlist_memory;
	px->nextstate_memory += p->nextstate_memory;
	px->failstate_memory += p->failstate_memory;
}

