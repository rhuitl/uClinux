/*
array.c 
copyright 1991-96, Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
*/

/*
This file was generated with the command

   notangle -R'"array.c"' array.w > array.c

Notangle is part of Norman Ramsey's noweb literate programming package
available from CTAN(ftp.shsu.edu).

It's easiest to read or modify this file by working with array.w.
*/

#include "mawk.h"
#include "symtype.h"
#include "memory.h"
#include "field.h"
#include "bi_vars.h"
struct anode ;
typedef struct {struct anode *slink, *ilink ;} DUAL_LINK ;

typedef struct anode {
   struct anode *slink ;
   struct anode  *ilink ;
   STRING *sval ;
   unsigned hval ;
   Int     ival ;
   CELL    cell ;
} ANODE ;


#define NOT_AN_IVALUE (-Max_Int-1)  /* usually 0x80000000 */

#define STARTING_HMASK    63  /* 2^6-1, must have form 2^n-1 */
#define MAX_AVE_LIST_LENGTH   12
#define hmask_to_limit(x) (((x)+1)*MAX_AVE_LIST_LENGTH)

static ANODE* PROTO(find_by_ival,(ARRAY, Int, int)) ;
static ANODE* PROTO(find_by_sval,(ARRAY, STRING*, int)) ;
static void PROTO(add_string_associations,(ARRAY)) ;
static void PROTO(make_empty_table,(ARRAY, int)) ;
static void PROTO(convert_split_array_to_table,(ARRAY)) ;
static void PROTO(double_the_hash_table,(ARRAY)) ;
static unsigned PROTO(ahash, (STRING*)) ;


CELL* array_find(A, cp, create_flag)
   ARRAY A ;
   CELL *cp ;
   int create_flag ;
{
   ANODE *ap ;
   if (A->size == 0 && !create_flag) 
      /* eliminating this trivial case early avoids unnecessary conversions later */
      return (CELL*) 0 ;
   switch (cp->type) {
      case C_DOUBLE:
         {
            double d = cp->dval ;
            Int ival = d_to_I(d) ;
            if ((double)ival == d) {
               if (A->type == AY_SPLIT) {
                  if (ival >= 1 && ival <= A->size) 
                     return (CELL*)A->ptr+(ival-1) ;
                  if (!create_flag) return (CELL*) 0 ;
                  convert_split_array_to_table(A) ;
               }
               else if (A->type == AY_NULL) make_empty_table(A, AY_INT) ;
               ap = find_by_ival(A, ival, create_flag) ;
            }
            else {
               /* convert to string */
               char buff[260] ;
               STRING *sval ;
               sprintf(buff, string(CONVFMT)->str, d) ;
               sval = new_STRING(buff) ;
               ap = find_by_sval(A,sval,create_flag) ;
               free_STRING(sval) ;
            }
         }

         break ;
      case C_NOINIT:
         ap = find_by_sval(A, &null_str, create_flag) ;
         break ;
      default:
         ap = find_by_sval(A, string(cp), create_flag) ;
         break ;
   }
   return ap ? &ap->cell : (CELL *) 0 ;
}

void array_delete(A, cp)
   ARRAY A ;
   CELL *cp ;
{
   ANODE *ap ;
   if (A->size == 0) return ; 
   switch(cp->type) {
      case C_DOUBLE :
         {
            double d = cp->dval ;
            Int ival = d_to_I(d) ;
            if ((double)ival == d) {
                                      if (A->type == AY_SPLIT)
                                         if (ival >=1 && ival <= A->size) convert_split_array_to_table(A) ;
                                         else return ; /* ival not in range */
                                      ap = find_by_ival(A, ival, NO_CREATE) ;
                                      if (ap) { /* remove from the front of the ilist */
                                         DUAL_LINK *table = (DUAL_LINK*) A->ptr ;
                                         table[ap->ival & A->hmask].ilink = ap->ilink ;
                                         if (ap->sval) {
                                            ANODE *p, *q = 0 ;
                                            int index = ap->hval & A->hmask ;
                                            p = table[index].slink ;
                                            while(p != ap) { q = p ; p = q->slink ; }
                                            if (q) q->slink = p->slink ;
                                            else table[index].slink = p->slink ;
                                            free_STRING(ap->sval) ;
                                         }

                                         cell_destroy(&ap->cell) ;
                                         ZFREE(ap) ;
                                         if (--A->size == 0) array_clear(A) ;


                                      }
                                      return ;
                                   }

            else { /* get the string value */
               char buff[260] ;
               STRING *sval ;
               sprintf(buff, string(CONVFMT)->str, d) ;
               sval = new_STRING(buff) ;
               ap = find_by_sval(A, sval, NO_CREATE) ;
               free_STRING(sval) ;
            }
         }
         break ;
      case C_NOINIT :
         ap = find_by_sval(A, &null_str, NO_CREATE) ;
         break ;
      default :
         ap = find_by_sval(A, string(cp), NO_CREATE) ;
         break ;
   }
   if (ap) { /* remove from the front of the slist */
      DUAL_LINK *table = (DUAL_LINK*) A->ptr ;
      table[ap->hval&A->hmask].slink = ap->slink ;
      if (ap->ival != NOT_AN_IVALUE) {
         ANODE *p, *q = 0 ;
         int index = ap->ival & A->hmask ;
         p = table[index].ilink ;
         while(p != ap) { q = p ; p = q->ilink ; }
         if (q) q->ilink = p->ilink ;
         else table[index].ilink = p->ilink ;
      }

      free_STRING(ap->sval) ;
      cell_destroy(&ap->cell) ;
      ZFREE(ap) ;
      if (--A->size == 0) array_clear(A) ;


   }
}

void array_load(A, cnt)
   ARRAY A ;
   int cnt ;
{
   CELL *cells ; /* storage for A[1..cnt] */
   int i ;  /* index into cells[] */
   if (A->type != AY_SPLIT || A->limit < cnt) {
      array_clear(A) ;
      A->limit = (cnt&~3)+4 ;
      A->ptr = zmalloc(A->limit*sizeof(CELL)) ;
      A->type = AY_SPLIT ;
   }
   else
      for(i=0;i < A->size; i++)  cell_destroy((CELL*)A->ptr+i) ;

   cells = (CELL*) A->ptr ;
   A->size = cnt ;
   if (cnt > MAX_SPLIT) {
      SPLIT_OV *p = split_ov_list ;
      SPLIT_OV *q ;
      split_ov_list = (SPLIT_OV*) 0 ;
      i = MAX_SPLIT ;  
      while( p ) {
         cells[i].type = C_MBSTRN ;
         cells[i].ptr = (PTR) p->sval ;
         q = p ; p = q->link ; ZFREE(q) ;
         i++ ;
      }
      cnt = MAX_SPLIT ;
   }

   for(i=0;i < cnt; i++) {
      cells[i].type = C_MBSTRN ;
      cells[i].ptr = split_buff[i] ;
   }
}

void array_clear(A)
   ARRAY A ;
{
   int i ;
   ANODE *p, *q ;
   if (A->type == AY_SPLIT) {
      for(i=0;i < A->size; i++) cell_destroy((CELL*)A->ptr+i) ;
      zfree(A->ptr, A->limit * sizeof(CELL)) ;
   }
   else if (A->type & AY_STR) {
      DUAL_LINK *table = (DUAL_LINK*) A->ptr ;
      for(i=0;i <= A->hmask; i++) {
         p = table[i].slink ;
         while(p) {
            q = p ; p = q->slink ;
            free_STRING(q->sval) ;
            cell_destroy(&q->cell) ;
            ZFREE(q) ;
         }
      }
      zfree(A->ptr, (A->hmask+1)*sizeof(DUAL_LINK)) ;
   }
   else if (A->type & AY_INT) {
      DUAL_LINK *table = (DUAL_LINK*) A->ptr ;
      for(i=0;i <= A->hmask; i++) {
         p = table[i].ilink ;
         while(p) {
            q = p ; p = q->ilink ;
            cell_destroy(&q->cell) ;
            ZFREE(q) ;
         }
      }
      zfree(A->ptr, (A->hmask+1)*sizeof(DUAL_LINK)) ;
   }
   memset(A, 0, sizeof(*A)) ;
}



STRING** array_loop_vector(A, sizep)
   ARRAY A ;
   unsigned *sizep ;
{
   STRING** ret ;
   *sizep = A->size ;
   if (A->size > 0) {
      if (!(A->type & AY_STR)) add_string_associations(A) ;
      ret = (STRING**) zmalloc(A->size*sizeof(STRING*)) ;
      {
         int r = 0 ; /* indexes ret */
         DUAL_LINK* table = (DUAL_LINK*) A->ptr ;
         int i ; /* indexes table */
         ANODE *p ; /* walks slists */
         for(i=0;i <= A->hmask; i++) {
            for(p = table[i].slink; p ; p = p->slink) {
               ret[r++] = p->sval ;
               p->sval->ref_cnt++ ;
            }
         }
      }

      return ret ;
   }
   else return (STRING**) 0 ;
}

CELL *array_cat(sp, cnt)
   CELL *sp ;
   int cnt ;
{
   CELL *p ;  /* walks the eval stack */
   CELL subsep ;  /* local copy of SUBSEP */
   unsigned subsep_len ; /* string length of subsep_str */
   char *subsep_str ;   

   unsigned total_len ;  /* length of cat'ed expression */
   CELL *top ;   /* value of sp at entry */
   char *target ;  /* build cat'ed char* here */
   STRING *sval ;  /* build cat'ed STRING here */
   cellcpy(&subsep, SUBSEP) ;
   if ( subsep.type < C_STRING ) cast1_to_s(&subsep) ;
   subsep_len = string(&subsep)->len ;
   subsep_str = string(&subsep)->str ;

   top = sp ; sp -= (cnt-1) ;

   total_len = (cnt-1)*subsep_len ;
   for(p = sp ; p <= top ; p++) {
      if ( p->type < C_STRING ) cast1_to_s(p) ;
      total_len += string(p)->len ;
   }

   sval = new_STRING0(total_len) ;
   target = sval->str ;
   for(p = sp ; p < top ; p++) {
      memcpy(target, string(p)->str, string(p)->len) ;
      target += string(p)->len ;
      memcpy(target, subsep_str, subsep_len) ;
      target += subsep_len ;
   }
   /* now p == top */
   memcpy(target, string(p)->str, string(p)->len) ;

   for(p = sp; p <= top ; p++) free_STRING(string(p)) ;
   free_STRING(string(&subsep)) ;
   /* set contents of sp , sp->type > C_STRING is possible so reset */
   sp->type = C_STRING ; 
   sp->ptr = (PTR) sval ;
   return sp ;

}

static ANODE* find_by_ival(A, ival, create_flag)
   ARRAY A ;
   Int ival ;
   int create_flag ;
{
   DUAL_LINK *table = (DUAL_LINK*) A->ptr ;
   unsigned index = ival & A->hmask ;
   ANODE *p = table[index].ilink ; /* walks ilist */
   ANODE *q = (ANODE*) 0 ; /* trails p */
   while(1) {
      if (!p) {
          /* search failed */
          if (A->type & AY_STR) {
             /* need to search by string */
             char buff[256] ;
             STRING *sval ;
             sprintf(buff, INT_FMT, ival) ;
             sval = new_STRING(buff) ;
             p = find_by_sval(A, sval, create_flag) ;
             free_STRING(sval) ;
             if (!p) return (ANODE*) 0 ;
          }
          else if (create_flag) {
             p = ZMALLOC(ANODE) ;
             p->sval = (STRING*) 0 ;
             p->cell.type = C_NOINIT ;
             if (++A->size > A->limit) {
                double_the_hash_table(A) ; /* changes table, may change index */
                table = (DUAL_LINK*) A->ptr ;
                index = A->hmask & ival ;
             }
          }
          else return (ANODE*) 0 ;
          p->ival = ival ;
          A->type |= AY_INT ;

          break ;
      }
      else if (p->ival == ival) { 
         /* found it, now move to the front */
         if (!q) /* already at the front */
            return p ;
         /* delete for insertion at the front */
         q->ilink = p->ilink ;
         break ;
      }
      q = p ; p = q->ilink ;
   }
   /* insert at the front */
   p->ilink = table[index].ilink ;
   table[index].ilink = p ;
   return p ;
}

static ANODE* find_by_sval(A, sval, create_flag)
   ARRAY A ;
   STRING *sval ;
   int create_flag ;
{
   unsigned hval = ahash(sval) ;
   char *str = sval->str ;
   DUAL_LINK *table ;
   int index ;
   ANODE *p ;  /* walks list */
   ANODE *q = (ANODE*) 0 ; /* trails p */
   if (! (A->type & AY_STR)) add_string_associations(A) ;
   table = (DUAL_LINK*) A->ptr ;
   index = hval & A->hmask ;
   p = table[index].slink ;
   while(1) {
      if (!p)  {
         if (create_flag) {
            {
               p = ZMALLOC(ANODE) ;
               p->sval = sval ;
               sval->ref_cnt++ ;
               p->ival = NOT_AN_IVALUE ;
               p->hval = hval ;
               p->cell.type = C_NOINIT ;
               if (++A->size > A->limit) {
                  double_the_hash_table(A) ; /* changes table, may change index */
                  table = (DUAL_LINK*) A->ptr ;
                  index = hval & A->hmask ;
               }
            }

            break ;
         }
         else return (ANODE*) 0 ;
      }
      else if (p->hval == hval && strcmp(p->sval->str,str) == 0 ) {
         /* found */
         if (!q) /* already at the front */
            return p ;
         else { /* delete for move to the front */
            q->slink = p->slink ;
            break ;
         }
      }
      q = p ; p = q->slink ;
   }
   p->slink = table[index].slink ;
   table[index].slink = p ;
   return p ;
}

static void add_string_associations(A)
   ARRAY A ;
{
   if (A->type == AY_NULL) make_empty_table(A, AY_STR) ;
   else {
      DUAL_LINK *table ;
      int i ; /* walks table */
      ANODE *p ; /* walks ilist */
      char buff[256] ;
      if (A->type == AY_SPLIT) convert_split_array_to_table(A) ;
      table = (DUAL_LINK*) A->ptr ;
      for(i=0;i <= A->hmask; i++) {
         p = table[i].ilink ;
         while(p) {
            sprintf(buff, INT_FMT, p->ival) ;
            p->sval = new_STRING(buff) ;
            p->hval = ahash(p->sval) ;
            p->slink = table[A->hmask&p->hval].slink ;
            table[A->hmask&p->hval].slink = p ;
            p = p->ilink ;
         }
      }
      A->type |= AY_STR ;
   }
}

static void make_empty_table(A, type)
   ARRAY A ;
   int type ; /* AY_INT or AY_STR */
{
   size_t sz = (STARTING_HMASK+1)*sizeof(DUAL_LINK) ;
   A->type = type ;
   A->hmask = STARTING_HMASK ;
   A->limit = hmask_to_limit(STARTING_HMASK) ;
   A->ptr = memset(zmalloc(sz), 0, sz) ;
}

static void convert_split_array_to_table(A)
   ARRAY A ;
{
   CELL *cells = (CELL*) A->ptr ;
   int i ; /* walks cells */
   DUAL_LINK *table ;
   int j ; /* walks table */
   unsigned entry_limit = A->limit ;
   A->hmask = STARTING_HMASK ;
   A->limit = hmask_to_limit(STARTING_HMASK) ;
   while(A->size > A->limit) {
      A->hmask = (A->hmask<<1) + 1 ; /* double the size */
      A->limit = hmask_to_limit(A->hmask) ;
   }
   {
      size_t sz = (A->hmask+1)*sizeof(DUAL_LINK) ;
      A->ptr = memset(zmalloc(sz), 0, sz) ;
      table = (DUAL_LINK*) A->ptr ;
   }


   /* insert each cells[i] in the new hash table on an ilist */
   for(i=0, j=1 ;i < A->size; i++) {
      ANODE *p = ZMALLOC(ANODE) ;
      p->sval = (STRING*) 0 ;
      p->ival = i+1 ;
      p->cell = cells[i] ;
      p->ilink = table[j].ilink ;
      table[j].ilink = p ;
      j++ ; j &= A->hmask ;
   }
   A->type = AY_INT ;
   zfree(cells, entry_limit*sizeof(CELL)) ;
}

static void double_the_hash_table(A)
   ARRAY A ;
{
   unsigned old_hmask = A->hmask ;
   unsigned new_hmask = (old_hmask<<1)+1 ;
   DUAL_LINK *table ;
   A->ptr = zrealloc(A->ptr, (old_hmask+1)*sizeof(DUAL_LINK),
                             (new_hmask+1)*sizeof(DUAL_LINK)) ;
   table = (DUAL_LINK*) A->ptr ;
   /* zero out the new part which is the back half */
   memset(&table[old_hmask+1], 0, (old_hmask+1)*sizeof(DUAL_LINK)) ;

   if (A->type & AY_STR) {
      int i ; /* index to old lists */
      int j ; /* index to new lists */
      ANODE *p ; /* walks an old list */
      ANODE *q ; /* trails p for deletion */
      ANODE *tail ; /* builds new list from the back */
      ANODE dummy0, dummy1 ;
      for(i=0, j=old_hmask+1;i <= old_hmask; i++, j++) 
         {
            q = &dummy0 ;
            q->slink = p = table[i].slink ;
            tail = &dummy1 ;
            while (p) {
               if ((p->hval&new_hmask) != i) { /* move it */
                  q->slink = p->slink ;
                  tail = tail->slink = p ;
               }
               else q = p ;
               p = q->slink ;
            }
            table[i].slink = dummy0.slink ;
            tail->slink = (ANODE*) 0 ;
            table[j].slink = dummy1.slink ;
         }

   }

   if (A->type & AY_INT) {
      int i ; /* index to old lists */
      int j ; /* index to new lists */
      ANODE *p ; /* walks an old list */
      ANODE *q ; /* trails p for deletion */
      ANODE *tail ; /* builds new list from the back */
      ANODE dummy0, dummy1 ;
      for(i=0, j=old_hmask+1;i <= old_hmask; i++, j++) 
         {
            q = &dummy0 ;
            q->ilink = p = table[i].ilink ;
            tail = &dummy1 ;
            while (p) {
               if ((p->ival&new_hmask) != i) { /* move it */
                  q->ilink = p->ilink ;
                  tail = tail->ilink = p ;
               }
               else q = p ;
               p = q->ilink ;
            }
            table[i].ilink = dummy0.ilink ;
            tail->ilink = (ANODE*) 0 ;
            table[j].ilink = dummy1.ilink ;
         }

   }

   A->hmask = new_hmask ;
   A->limit = hmask_to_limit(new_hmask) ;
}


static unsigned ahash(sval)
   STRING* sval ;
{
   unsigned sum1 = sval->len ;
   unsigned sum2 = sum1 ;
   unsigned char *p , *q ;
   if (sum1 <= 10) {
      for(p=(unsigned char*)sval->str; *p ; p++) {
         sum1 += sum1 + *p ;
         sum2 += sum1 ;
      }
   }
   else {
      int cnt = 5 ;
      p = (unsigned char*)sval->str ; /* p starts at the front */
      q = (unsigned char*)sval->str + (sum1-1) ; /* q starts at the back */
      while( cnt ) {
         cnt-- ;
         sum1 += sum1 + *p ;
         sum2 += sum1 ;
         sum1 += sum1 + *q ;
         sum2 += sum1 ;
         p++ ; q-- ;
      }
   }
   return sum2 ;
}



