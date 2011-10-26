/*
*  ksearch.c
*  
*  Basic Keyword Search Trie - uses linked lists to build the finite automata
*
*  Keyword-Match: Performs the equivalent of a multi-string strcmp() 
*     - use for token testing after parsing the language tokens using lex or the like.
*
*  Keyword-Search: searches the input text for one of multiple keywords, 
*  and supports case sensitivite and case insensitive patterns.
*   
*
**  Copyright (C) 2001 Marc Norton
** Copyright (C) 2003 Sourcefire, Inc
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
*
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ctype.h>

#include "sfksearch.h"

/*
*  Allocate Memory
*/
static void * KTRIE_MALLOC( int n )
{
   void * p;

   p = calloc( 1, n );

   return p;
}

/*
*  Free Memory
*/
/*
static void KTRIE_FREE( void * p )
{
   if( p ) free( p );
}
*/

/*
*   Local/Tmp nocase array
*/
static unsigned char Tnocase[65*1024];

/*
** Case Translation Table 
*/
static unsigned char xlatcase[256];

/*
*
*/
static void init_xlatcase()
{
   int i;
   static int first=1;

   if( !first ) return; /* thread safe */
   
   for(i=0;i<256;i++)
   {
     xlatcase[ i ] =  (unsigned char)tolower(i);
   }

   first=0;
}

/*
*
*/
static inline void ConvertCaseEx( unsigned char * d, unsigned char *s, int m )
{
     int i;
     for( i=0; i < m; i++ )
     {
       d[i] = xlatcase[ s[i] ];
     }
}


/*
*
*/
KTRIE_STRUCT * KTrieNew()
{
   KTRIE_STRUCT * ts = (KTRIE_STRUCT*) KTRIE_MALLOC( sizeof(KTRIE_STRUCT) );

   if( !ts ) return 0;
   
   memset(ts, 0, sizeof(KTRIE_STRUCT));  

   init_xlatcase();

   ts->memory = sizeof(KTRIE_STRUCT);
   ts->nchars = 0;
   ts->npats  = 0;

   return ts;
}

/*
*
*/
static KTRIEPATTERN * KTrieNewPattern(unsigned char * P, int n)
{
   KTRIEPATTERN *p = (KTRIEPATTERN*) KTRIE_MALLOC( sizeof(KTRIEPATTERN) );

   if( !p ) return 0;

   /* Save as a nocase string */   
   p->P = (unsigned char*) KTRIE_MALLOC( n );
   if( !p->P ) 
   {
       free(p); 
       return 0;
   }

   ConvertCaseEx( p->P, P, n );

   /* Save Case specific version */
   p->Pcase = (unsigned char*) KTRIE_MALLOC( n );
   if( !p->Pcase ) 
   {
       free(p->P); 
       free(p); 
       return 0;
   }

   memcpy( p->Pcase, P, n );
   
   p->n    = n;
   p->next = 0;

   return p;
}

/*
*  Add Pattern info to the list of patterns
*/
int KTrieAddPattern( KTRIE_STRUCT * ts, unsigned char * P, int n, 
                      int nocase, void * id )
{
   KTRIEPATTERN  *new;

   if( !ts->patrn )
   {
       new = ts->patrn = KTrieNewPattern( P, n );

       if( !new ) return -1;
   }
   else
   {
       new = KTrieNewPattern(P, n );

       if( !new ) return -1;

       new->next = ts->patrn; /* insert at head of list */

       ts->patrn = new;
   }

   new->nocase = nocase;
   new->id     = id;
   new->mnext  = NULL;

   ts->npats++;
   ts->memory += sizeof(KTRIEPATTERN) + 2 * n ; /* Case and nocase */
   
   return 1;
}


/*
*
*/
static KTRIENODE * KTrieCreateNode(KTRIE_STRUCT * ts)
{
   KTRIENODE * t=(KTRIENODE*)KTRIE_MALLOC( sizeof(KTRIENODE) );

   if(!t)
      return 0;

   memset(t,0,sizeof(KTRIENODE));

   ts->memory += sizeof(KTRIENODE);
   
   return t;
}


/*
*  Insert a Pattern in the Trie
*/
static int KTrieInsert( KTRIE_STRUCT *ts, KTRIEPATTERN * px  )
{
   int            type = 0;
   int            n = px->n;
   unsigned char *P = px->P;
   KTRIENODE     *root;
   
   /* Make sure we at least have a root character for the tree */
   if( !ts->root[*P] )
   {
      ts->root[*P] = root = KTrieCreateNode(ts);
      if( !root ) return -1;
      root->edge = *P;

   }else{

      root = ts->root[*P];
   }

   /* Walk existing Patterns */   
   while( n )
   {
     if( root->edge == *P )
     {
         P++;
         n--;

         if( n && root->child )
         {
            root=root->child;   
         }
         else /* cannot continue */
         {
            type = 0; /* Expand the tree via the child */
            break; 
         }
     }
     else
     {
         if( root->sibling )
         {
            root=root->sibling;
         }
         else /* cannot continue */
         {
            type = 1; /* Expand the tree via the sibling */
            break; 
         }
     }
   }

   /* 
   * Add the next char of the Keyword, if any
   */
   if( n )
   {
     if( type == 0 )
     {
      /*
      *  Start with a new child to finish this Keyword 
      */
      root->child= KTrieCreateNode( ts );
      if( ! root->child ) return -1;
      root=root->child;
      root->edge  = *P;
      P++;
      n--;
      ts->nchars++;

     }
     else
     { 
      /*
      *  Start a new sibling bracnch to finish this Keyword 
      */
      root->sibling= KTrieCreateNode( ts );
      if( ! root->sibling ) return -1;
      root=root->sibling;
      root->edge  = *P;
      P++;
      n--;
      ts->nchars++;
     }
   }

   /*
   *    Finish the keyword as child nodes
   */
   while( n )
   {
      root->child = KTrieCreateNode(ts);
      if( ! root->child ) return -1;
      root=root->child;
      root->edge  = *P;
      P++;
      n--;
      ts->nchars++;
   }

   if( root->pkeyword )
   {
      px->mnext = root->pkeyword;  /* insert duplicates at front of list */
      root->pkeyword = px;
      ts->duplicates++;
   }
   else
   {
      root->pkeyword = px;
   }

   return 0;
}


/*
*
*/
static void Build_Bad_Character_Shifts( KTRIE_STRUCT * kt )
{
    int           i,k;
    KTRIEPATTERN *plist; 

    /* Calc the min pattern size */
    kt->bcSize = 32000;

    for( plist=kt->patrn; plist!=NULL; plist=plist->next )
    { 
      if( plist->n < kt->bcSize )     
      {
          kt->bcSize = plist->n; /* smallest pattern size */
      }
    }

    /*
    *  Initialze the Bad Character shift table.  
    */
    for(i=0;i<256;i++)
    {
      kt->bcShift[i] = (unsigned short)kt->bcSize;  
    }

    /* 
    *  Finish the Bad character shift table
    */  
    for( plist=kt->patrn; plist!=NULL; plist=plist->next )
    {
       int shift, cindex;

       for( k=0; k<kt->bcSize; k++ )
       {
          shift = kt->bcSize - 1 - k;

          cindex = plist->P[ k ];

          if( shift < kt->bcShift[ cindex ] )
	  {
              kt->bcShift[ cindex ] = (unsigned short)shift;
	  }
       }
    }
}


/*
*  Build the Keyword TRIE
*  
*/
int KTrieCompile(KTRIE_STRUCT * ts)
{
  KTRIEPATTERN * p;
  /*
  static int  tmem=0; 
  */

  /* 
  *    Build the Keyword TRIE 
  */
  for( p=ts->patrn; p; p=p->next )
  {
       if( KTrieInsert( ts, p ) )
       return -1;
  }

  /*
  *    Build A Setwise Bad Character Shift Table
  */
  Build_Bad_Character_Shifts( ts );

  /*
  tmem += ts->memory;
  printf(" Compile stats: %d patterns, %d chars, %d duplicate patterns, %d bytes, %d total-bytes\n",ts->npats,ts->nchars,ts->duplicates,ts->memory,tmem);
  */

  return 0;
}

/*
*   Search - Algorithm
*
*   This routine will log any substring of T that matches a keyword,
*   and processes all prefix matches. This is used for generic
*   pattern searching with a set of keywords and a body of text.
*
*   
*
*   kt- Trie Structure 
*   T - nocase text
*   Tc- case specific text
*   n - text length 
* 
*   returns:
*	# pattern matches
*/
static inline int KTriePrefixMatch( KTRIE_STRUCT  * kt, 
                                    unsigned char * T, 
                                    unsigned char * Tc, 
                                    unsigned char * bT, 
                                    int n,
       int(*match)( void * id,  int index, void * data ),
       void * data )
{
   KTRIENODE     * root   = kt->root[ *T ];
   int             nfound = 0;
   KTRIEPATTERN  * pk;
   int index ;

   /* Check if any keywords start with this character */
   if( !root ) return 0;
        
   while( n )
   {
     if( root->edge == *T )
     {
         T++;
         n--;

         for( pk = root->pkeyword; pk; pk= pk->mnext ) /* log each and every prefix match */
         {
            index = (int)(T - bT - pk->n );

            if( pk->nocase )
            {
                nfound++;
                if( match( pk->id, index, data ) )
                  return nfound;
            }
            else
            {   /* Retest with a Case Sensitive Test */
		if( !memcmp(pk->Pcase,Tc,pk->n) )
		{
                  nfound++;
                  if( match( pk->id, index, data ) )
                    return nfound;
		}
            }
         }

         if( n && root->child )
         {
            root = root->child;   
         }
         else /* cannot continue -- match is over */
         {
            break; 
         }
     }
     else
     {
         if( root->sibling )
         {
            root = root->sibling;
         }
         else /* cannot continue */
         {
            break; 
         }
     }
   }

   return nfound;
}

/*
*
*/
static inline int KTrieSearchNoBC( KTRIE_STRUCT * ks, unsigned char * Tx, int n, 
              int(*match)( void *  id,  int index, void * data ), void * data )
{
   int            nfound = 0;
   unsigned char *T, *bT;

   ConvertCaseEx( Tnocase, Tx, n );

   T  = Tnocase;
   bT = T;

   for( ; n>0 ; n--, T++, Tx++ )
   {
      nfound += KTriePrefixMatch( ks, T, Tx, bT, n, match, data );
   }

   return nfound;
}

/*
*
*/
static inline int KTrieSearchBC( KTRIE_STRUCT * ks, unsigned char * Tx, int n,
              int(*match)( void * id,  int index, void * data ), void * data )
{
   int             tshift;
   unsigned char  *Tend;
   unsigned char  *T, *bT;
   int             nfound  = 0; 
   short          *bcShift = (short*)ks->bcShift;
   int             bcSize  = ks->bcSize;

   ConvertCaseEx( Tnocase, Tx, n );

   T  = Tnocase;
   bT = T;

   Tend = T + n - bcSize;

   bcSize--;

   for( ;T <= Tend; n--, T++, Tx++ )
   {
       while( (tshift = bcShift[ *( T + bcSize ) ]) > 0 ) 
       {
          T  += tshift;
          Tx += tshift;
          if( T > Tend ) return nfound;
       }

       nfound += KTriePrefixMatch( ks, T, Tx, bT, n, match, data );
   }

   return nfound;
}

/*
*
*/
int KTrieSearch( KTRIE_STRUCT * ks, unsigned char * T, int n, 
    int(*match)( void * id,  int index, void * data ), void * data )
{  
    if( ks->bcSize < 3)
        return KTrieSearchNoBC( ks, T, n, match, data );
    else
        return KTrieSearchBC( ks, T, n, match, data );
}

/*
*
*    TEST DRIVER FOR KEYWORD TRIE
*
*/
#ifdef KTRIE_MAIN

char ** gargv;

int trie_nmatches = 0;

int match( unsigned id, int index, void * data )
{
   trie_nmatches++;
   data = data;
   printf("id=%d found at index=%d, %s\n",id,index,gargv[id]);
   return 0;
}

/*
*
*/
int main( int argc, char ** argv )
{
    int i;
    KTRIE_STRUCT * ts;
    int nocase=1;  // don't care about case

    gargv = argv;
    
    ts = KTrieNew();

    if( argc < 3 )
    {
        printf("%s text pat1 pat2 ... patn [-c(ase-sensitive)\n",argv[0]);
        printf("search for keywords-default, or match keywords\n");
        exit(0); 
    }

    for(i=1;i<argc;i++)
    {    
       if( strcmp(argv[i],"-c")==0 ) nocase=0; /* ignore case */
    }

    printf("New TRIE created\n");

    for(i=2;i<argc;i++)
    {
       if( argv[i][0]=='-' ) 
           continue;

       KTrieAddPattern( ts, (unsigned char *)argv[i], strlen(argv[i]), nocase, i );
    }
    
    printf("Patterns added \n");

    KTrieCompile( ts );

    printf("Patterns compiled \n");
    printf("--> %d characters, %d patterns, %d bytes allocated\n",ts->nchars,ts->npats,ts->memory);

    printf("Searching...\n");

    KTrieSearch( ts, (unsigned char*)argv[1], strlen(argv[1]), match, 0 );

    printf("%d matches found\n",trie_nmatches);

    printf("normal pgm finish.\n");
     
    return 0;
}

#endif
