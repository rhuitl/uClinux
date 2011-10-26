
/********************************************
hash.c
copyright 1991, Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/


/* $Log: hash.c,v $
 * Revision 1.3  1994/10/08  19:15:43  mike
 * remove SM_DOS
 *
 * Revision 1.2  1993/07/16  00:17:35  mike
 * cleanup
 *
 * Revision 1.1.1.1  1993/07/03	 18:58:14  mike
 * move source to cvs
 *
 * Revision 5.1	 1991/12/05  07:56:05  brennan
 * 1.1 pre-release
 *
*/


/* hash.c */

#include "mawk.h"
#include "memory.h"
#include "symtype.h"


unsigned
hash(s)
   register char *s ;
{
   register unsigned h = 0 ;

   while (*s)  h += h + *s++ ;
   return h ;
}

typedef struct hash
{
   struct hash *link ;
   SYMTAB symtab ;
} HASHNODE ;

static HASHNODE *PROTO(delete, (char *)) ;

static HASHNODE *hash_table[HASH_PRIME] ;

/*
insert a string in the symbol table.
Caller knows the symbol is not there
-- used for initialization
*/

SYMTAB *
insert(s)
   char *s ;
{
   register HASHNODE *p = ZMALLOC(HASHNODE) ;
   register unsigned h ;

   p->link = hash_table[h = hash(s) % HASH_PRIME] ;
   p->symtab.name = s ;
   hash_table[h] = p ;
   return &p->symtab ;
}

/* Find s in the symbol table,
   if not there insert it,  s must be dup'ed  */

SYMTAB *
find(s)
   char *s ;
{
   register HASHNODE *p ;
   HASHNODE *q ;
   unsigned h ;

   p = hash_table[h = hash(s) % HASH_PRIME] ;
   q = (HASHNODE *) 0 ;
   while (1)
   {
      if (!p)
      {
	 p = ZMALLOC(HASHNODE) ;
	 p->symtab.type = ST_NONE ;
	 p->symtab.name = strcpy(zmalloc(strlen(s) + 1), s) ;
	 break ;
      }

      if (strcmp(p->symtab.name, s) == 0)	/* found */
      {
	 if (!q)		/* already at the front */
	    return &p->symtab ;
	 else  /* delete from the list */
	 {
	    q->link = p->link ;	 break ; 
	 }
      }

      q = p ; p = p->link ;
   }
   /* put p on front of the list */
   p->link = hash_table[h] ;
   hash_table[h] = p ;
   return &p->symtab ;
}


/* remove a node from the hash table
   return a ptr to the node */

static unsigned last_hash ;

static HASHNODE *
delete(s)
   char *s ;
{
   register HASHNODE *p ;
   HASHNODE *q = (HASHNODE *) 0 ;
   unsigned h ;

   p = hash_table[last_hash = h = hash(s) % HASH_PRIME] ;
   while (p)
   {
      if (strcmp(p->symtab.name, s) == 0)	/* found */
      {
	 if (q)	 q->link = p->link ;
	 else  hash_table[h] = p->link ;
	 return p ;
      }
      else
      {
	 q = p ; p = p->link ; 
      }
   }

#ifdef	DEBUG			/* we should not ever get here */
   bozo("delete") ;
#endif
   return (HASHNODE *) 0 ;
}

/* when processing user functions,  global ids which are
   replaced by local ids are saved on this list */

static HASHNODE *save_list ;

/* store a global id on the save list,
   return a ptr to the local symtab  */
SYMTAB *
save_id(s)
   char *s ;
{
   HASHNODE *p, *q ;
   unsigned h ;

   p = delete(s) ;
   q = ZMALLOC(HASHNODE) ;
   q->symtab.type = ST_LOCAL_NONE ;
   q->symtab.name = p->symtab.name ;
   /* put q in the hash table */
   q->link = hash_table[h = last_hash] ;
   hash_table[h] = q ;

   /* save p */
   p->link = save_list ; save_list = p ;

   return &q->symtab ;
}

/* restore all global indentifiers */
void
restore_ids()
{
   register HASHNODE *p, *q ;
   register unsigned h ;

   q = save_list ; save_list = (HASHNODE *) 0 ;
   while (q)
   {
      p = q ; q = q->link ;
      zfree(delete(p->symtab.name), sizeof(HASHNODE)) ;
      p->link = hash_table[h = last_hash] ;
      hash_table[h] = p ;
   }
}


/* search the symbol table backwards for the
   disassembler.  This is slow -- so what
*/


char *
reverse_find(type, ptr)
   int type ;
   PTR ptr ;
{
   CELL *cp ;
   ARRAY array ;
   static char uk[] = "unknown" ;

   int i ;
   HASHNODE *p ;


   switch (type)
   {
      case ST_VAR:
      case ST_FIELD:
	 cp = *(CELL **) ptr ;
	 break ;

      case ST_ARRAY:
	 array = *(ARRAY *) ptr ;
	 break ;

      default:
	 return uk ;
   }

   for (i = 0; i < HASH_PRIME; i++)
   {
      p = hash_table[i] ;
      while (p)
      {
	 if (p->symtab.type == type)
	 {
	    switch (type)
	    {
	       case ST_VAR:
	       case ST_FIELD:
		  if (cp == p->symtab.stval.cp)
		     return p->symtab.name ;
		  break ;

	       case ST_ARRAY:
		  if (array == p->symtab.stval.array)
		     return p->symtab.name ;
		  break ;
	    }
	 }

	 p = p->link ;
      }
   }
   return uk ;
}

