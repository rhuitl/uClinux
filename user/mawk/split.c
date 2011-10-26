
/********************************************
split.c
copyright 1991, Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/

/* $Log: split.c,v $
 * Revision 1.3  1996/02/01  04:39:42  mike
 * dynamic array scheme
 *
 * Revision 1.2  1993/07/15  01:55:03  mike
 * rm SIZE_T & indent
 *
 * Revision 1.1.1.1  1993/07/03	 18:58:21  mike
 * move source to cvs
 *
 * Revision 5.4	 1993/05/08  18:06:00  mike
 * null_split
 *
 * Revision 5.3	 1993/01/01  21:30:48  mike
 * split new_STRING() into new_STRING and new_STRING0
 *
 * Revision 5.2	 1992/07/08  21:19:09  brennan
 * patch2
 * change in split() requires that
 * bi_split() call load_array() even
 * when cnt is 0.
 *
 * Revision 5.1	 1991/12/05  07:56:31  brennan
 * 1.1 pre-release
 *
*/

/* split.c */


/* For all splitting up to MAX_SPLIT fields go into
   split_buff[], the rest go onto split_ov_list ( split
   overflow list)

   We can split one of three ways:
     (1) By space:
	 space_split() and space_ov_split()
     (2) By regular expression:
	 re_split()    and re_ov_split()
     (3) By "" (null -- split into characters)
	 null_split() and null_ov_split()
*/

#define	 TEMPBUFF_GOES_HERE

#include "mawk.h"
#include "symtype.h"
#include "bi_vars.h"
#include "bi_funct.h"
#include "memory.h"
#include "scan.h"
#include "regexp.h"
#include "field.h"

SPLIT_OV *split_ov_list ;

static int PROTO(re_ov_split, (char *, PTR)) ;
static int PROTO(space_ov_split, (char *, char *)) ;
static int PROTO(null_ov_split, (char *)) ;

/* split string s of length slen on SPACE without changing s.
   load the pieces into STRINGS and ptrs into
   split_buff[]
   return the number of pieces */

int
space_split(s, slen)
   register char *s ;
   unsigned slen ;
{
   char *back = s + slen ;
   int i = 0 ;
   int len ;
   char *q ;
   STRING *sval ;
   int lcnt = MAX_SPLIT / 3 ;

#define EAT_SPACE()   while ( scan_code[*(unsigned char*)s] ==\
			      SC_SPACE )  s++
#define EAT_NON_SPACE()	  \
    *back = ' ' ; /* sentinel */\
    while ( scan_code[*(unsigned char*)s] != SC_SPACE )	 s++ ;\
    *back = 0


   while (lcnt--)
   {
      EAT_SPACE() ;
      if (*s == 0)  goto done ;
      /* mark the front with q */
      q = s++ ;
      EAT_NON_SPACE() ;
      sval = split_buff[i++] = new_STRING0(len = s - q) ;
      memcpy(sval->str, q, len) ;

      EAT_SPACE() ;
      if (*s == 0)  goto done ;
      q = s++ ;
      EAT_NON_SPACE() ;
      sval = split_buff[i++] = new_STRING0(len = s - q) ;
      memcpy(sval->str, q, len) ;

      EAT_SPACE() ;
      if (*s == 0)  goto done ;
      q = s++ ;
      EAT_NON_SPACE() ;
      sval = split_buff[i++] = new_STRING0(len = s - q) ;
      memcpy(sval->str, q, len) ;

   }
   /* we've overflowed */
   return i + space_ov_split(s, back) ;

 done:
   return i ;
}

static int
space_ov_split(s, back)
   register char *s ;
   char *back ;

{
   SPLIT_OV dummy ;
   register SPLIT_OV *tail = &dummy ;
   char *q ;
   int cnt = 0 ;
   unsigned len ;

   while (1)
   {
      EAT_SPACE() ;
      if (*s == 0)  break ;		    /* done */
      q = s++ ;
      EAT_NON_SPACE() ;

      tail = tail->link = ZMALLOC(SPLIT_OV) ;
      tail->sval = new_STRING0(len = s - q) ;
      memcpy(tail->sval->str, q, len) ;
      cnt++ ;
   }

   tail->link = (SPLIT_OV *) 0 ;
   split_ov_list = dummy.link ;
   return cnt ;
}

/* match a string with a regular expression, but
   only matches of positive length count */
char *
re_pos_match(s, re, lenp)
   register char *s ;
PTR re ; unsigned *lenp ;
{
   while (s = REmatch(s, re, lenp))
      if (*lenp)  return s ;
      else if (*s == 0)	 break ;
      else  s++ ;

   return (char *) 0 ;
}

int
re_split(s, re)
   char *s ;
   PTR re ;
{
   register char *t ;
   int i = 0 ;
   unsigned mlen, len ;
   STRING *sval ;
   int lcnt = MAX_SPLIT / 3 ;

   while (lcnt--)
   {
      if (!(t = re_pos_match(s, re, &mlen)))  goto done ;
      sval = split_buff[i++] = new_STRING0(len = t - s) ;
      memcpy(sval->str, s, len) ;
      s = t + mlen ;

      if (!(t = re_pos_match(s, re, &mlen)))  goto done ;
      sval = split_buff[i++] = new_STRING0(len = t - s) ;
      memcpy(sval->str, s, len) ;
      s = t + mlen ;

      if (!(t = re_pos_match(s, re, &mlen)))  goto done ;
      sval = split_buff[i++] = new_STRING0(len = t - s) ;
      memcpy(sval->str, s, len) ;
      s = t + mlen ;
   }
   /* we've overflowed */
   return i + re_ov_split(s, re) ;

done:
   split_buff[i++] = new_STRING(s) ;
   return i ;
}

/*
  we've overflowed split_buff[] , put
  the rest on the split_ov_list
  return number of pieces
*/

static int
re_ov_split(s, re)
   char *s ;
   PTR re ;
{
   SPLIT_OV dummy ;
   register SPLIT_OV *tail = &dummy ;
   int cnt = 1 ;
   char *t ;
   unsigned len, mlen ;

   while (t = re_pos_match(s, re, &mlen))
   {
      tail = tail->link = ZMALLOC(SPLIT_OV) ;
      tail->sval = new_STRING0(len = t - s) ;
      memcpy(tail->sval->str, s, len) ;
      s = t + mlen ;
      cnt++ ;
   }
   /* and one more */
   tail = tail->link = ZMALLOC(SPLIT_OV) ;
   tail->sval = new_STRING(s) ;
   tail->link = (SPLIT_OV *) 0 ;
   split_ov_list = dummy.link ;

   return cnt ;
}


int
null_split(s)
   char *s ;
{
   int cnt = 0 ;		 /* number of fields split */
   STRING *sval ;
   int i = 0 ;			 /* indexes split_buff[] */

   while (*s)
   {
      if (cnt == MAX_SPLIT)  return cnt + null_ov_split(s) ;

      sval = new_STRING0(1) ;
      sval->str[0] = *s++ ;
      split_buff[i++] = sval ;
      cnt++ ;
   }
   return cnt ;
}

static int
null_ov_split(s)
   char *s ;
{
   SPLIT_OV dummy ;
   SPLIT_OV *ovp = &dummy ;
   int cnt = 0 ;

   while (*s)
   {
      ovp = ovp->link = ZMALLOC(SPLIT_OV) ;
      ovp->sval = new_STRING0(1) ;
      ovp->sval->str[0] = *s++ ;
      cnt++ ;
   }
   ovp->link = (SPLIT_OV *) 0 ;
   split_ov_list = dummy.link ;
   return cnt ;
}


/*  split(s, X, r)
    split s into array X on r

    entry: sp[0] holds r
	   sp[-1] pts at X
	   sp[-2] holds s
*/
CELL *
bi_split(sp)
   register CELL *sp ;
{
   int cnt ;			 /* the number of pieces */


   if (sp->type < C_RE)	 cast_for_split(sp) ;
   /* can be C_RE, C_SPACE or C_SNULL */
   sp -= 2 ;
   if (sp->type < C_STRING)  cast1_to_s(sp) ;

   if (string(sp)->len == 0)	/* nothing to split */
      cnt = 0 ;
   else
      switch ((sp + 2)->type)
      {
	 case C_RE:
	    cnt = re_split(string(sp)->str, (sp + 2)->ptr) ;
	    break ;

	 case C_SPACE:
	    cnt = space_split(string(sp)->str, string(sp)->len) ;
	    break ;

	 case C_SNULL:		/* split on empty string */
	    cnt = null_split(string(sp)->str) ;
	    break ;

	 default:
	    bozo("bad splitting cell in bi_split") ;
      }


   free_STRING(string(sp)) ;
   sp->type = C_DOUBLE ;
   sp->dval = (double) cnt ;

   array_load((ARRAY) (sp + 1)->ptr, cnt) ;

   return sp ;
}
