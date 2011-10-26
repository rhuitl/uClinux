/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>

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
*/

/***************************************************************************
 *
 * File: MSTRING.C
 *
 * Purpose: Provide a variety of string functions not included in libc.  Makes
 *          up for the fact that the libstdc++ is hard to get reference
 *          material on and I don't want to write any more non-portable c++
 *          code until I have solid references and libraries to use.
 *
 * History:
 *
 * Date:      Author:  Notes:
 * ---------- ------- ----------------------------------------------
 *  08/19/98    MFR    Initial coding begun
 *  03/06/99    MFR    Added Boyer-Moore pattern match routine, don't use
 *                     mContainsSubstr() any more if you don't have to
 *  12/31/99	JGW    Added a full Boyer-Moore implementation to increase
 *                     performance. Added a case insensitive version of mSearch
 *  07/24/01    MFR    Fixed Regex pattern matcher introduced by Fyodor
 *
 **************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#include "mstring.h"
#include "debug.h"
#include "plugbase.h" /* needed for fasthex() */
#include "util.h"

#ifdef GIDS
extern int detect_depth;
#endif /* GIDS */

extern u_int8_t *doe_ptr;

#ifdef TEST_MSTRING

int main()
{
    char test[] = "\0\0\0\0\0\0\0\0\0CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0";
    char find[] = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0";

/*   char test[] = "\x90\x90\x90\x90\x90\x90\xe8\xc0\xff\xff\xff/bin/sh\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
     char find[] = "\xe8\xc0\xff\xff\xff/bin/sh";  */
    int i;
    int toks;
    int *shift;
    int *skip;

/*   shift=make_shift(find,sizeof(find)-1);
     skip=make_skip(find,sizeof(find)-1); */

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,"%d\n",
			    mSearch(test, sizeof(test) - 1, find,
				    sizeof(find) - 1, shift, skip)););

    return 0;
}

#endif

/****************************************************************
 *
 *  Function: mSplit()
 *
 *  Purpose: Splits a string into tokens non-destructively.
 *
 *  Parameters:
 *      char *str => the string to be split
 *      char *sep => a string of token seperaters
 *      int max_strs => how many tokens should be returned
 *      int *toks => place to store the number of tokens found in str
 *      char meta => the "escape metacharacter", treat the character
 *                   after this character as a literal and "escape" a
 *                   seperator
 *
 *  Returns:
 *      2D char array with one token per "row" of the returned
 *      array.
 *
 ****************************************************************/
char **mSplit(char *str, char *sep, int max_strs, int *toks, char meta)
{
    char **retstr;      /* 2D array which is returned to caller */
    char *idx;          /* index pointer into str */
    char *end;          /* ptr to end of str */
    char *sep_end;      /* ptr to end of seperator string */
    char *sep_idx;      /* index ptr into seperator string */
    int len = 0;        /* length of current token string */
    int curr_str = 0;       /* current index into the 2D return array */
    char last_char = (char) 0xFF;

    if(!toks) return NULL;

    *toks = 0;

    if (!str) return NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "[*] Splitting string: %s\n", str);
            DebugMessage(DEBUG_PATTERN_MATCH, "curr_str = %d\n", curr_str););

    /*
     * find the ends of the respective passed strings so our while() loops
     * know where to stop
     */
    sep_end = sep + strlen(sep);
    end = str + strlen(str);

    /* remove trailing whitespace */
    while(isspace((int) *(end - 1)) && ((end - 1) >= str))
        *(--end) = '\0';    /* -1 because of NULL */

    /* set our indexing pointers */
    sep_idx = sep;
    idx = str;

    /*
     * alloc space for the return string, this is where the pointers to the
     * tokens will be stored
     */
    if((retstr = (char **) malloc((sizeof(char **) * max_strs))) == NULL)
        FatalPrintError("malloc");


    max_strs--;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "max_strs = %d  curr_str = %d\n", 
                max_strs, curr_str););

    /* loop thru each letter in the string being tokenized */
    while(idx < end)
    {
        /* loop thru each seperator string char */
        while(sep_idx < sep_end)
        {
            /*
             * if the current string-indexed char matches the current
             * seperator char...
             */
            if((*idx == *sep_idx) && (last_char != meta))
            {
                /* if there's something to store... */
                if(len > 0)
                {
                    DEBUG_WRAP(
                            DebugMessage(DEBUG_PATTERN_MATCH, 
                                "Allocating %d bytes for token ", len + 1););
                    if(curr_str <= max_strs)
                    {
                        /* allocate space for the new token */
                        if((retstr[curr_str] = (char *)
                                    malloc((sizeof(char) * len) + 1)) == NULL)
                        {
                            FatalPrintError("malloc");
                        }

                        /* copy the token into the return string array */
                        memcpy(retstr[curr_str], (idx - len), len);
                        retstr[curr_str][len] = 0;
                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "tok[%d]: %s\n", curr_str, 
                                    retstr[curr_str]););

                        /* twiddle the necessary pointers and vars */
                        len = 0;
                        curr_str++;
                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "curr_str = %d\n", curr_str);
                                DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "max_strs = %d  curr_str = %d\n", 
                                    max_strs, curr_str););

                        last_char = *idx;
                        idx++;
                    }

                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                "Checking if curr_str (%d) >= max_strs (%d)\n",
                               curr_str, max_strs););

                    /*
                     * if we've gotten all the tokens requested, return the
                     * list
                     */
                    if(curr_str >= max_strs)
                    {
                        while(isspace((int) *idx))
                            idx++;

                        len = end - idx;
                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Finishing up...\n");
                                DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Allocating %d bytes "
                                    "for last token ", len + 1););
                        fflush(stdout);

                        if((retstr[curr_str] = (char *)
                                    malloc((sizeof(char) * len) + 1)) == NULL)
                            FatalPrintError("malloc");

                        memcpy(retstr[curr_str], idx, len);
                        retstr[curr_str][len] = 0;

                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "tok[%d]: %s\n", curr_str, 
                                    retstr[curr_str]););

                        *toks = curr_str + 1;
                        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "max_strs = %d  curr_str = %d\n", 
                                    max_strs, curr_str);
                                DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "mSplit got %d tokens!\n", *toks););

                        return retstr;
                    }
                }
                else
                    /*
                     * otherwise, the previous char was a seperator as well,
                     * and we should just continue
                     */
                {
                    last_char = *idx;
                    idx++;
                    /* make sure to reset this so we test all the sep. chars */
                    sep_idx = sep;
                    len = 0;
                }
            }
            else
            {
                /* go to the next seperator */
                sep_idx++;
            }
        }

        sep_idx = sep;
        len++;
        last_char = *idx;
        idx++;
    }

    /* put the last string into the list */

    if(len > 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Allocating %d bytes for last token ", len + 1););

        if((retstr[curr_str] = (char *)
                    malloc((sizeof(char) * len) + 1)) == NULL)
            FatalPrintError("malloc");

        memcpy(retstr[curr_str], (idx - len), len);
        retstr[curr_str][len] = 0;

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,"tok[%d]: %s\n", curr_str, 
                    retstr[curr_str]););
        *toks = curr_str + 1;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "mSplit got %d tokens!\n", *toks););

    /* return the token list */
    return retstr;
}




/****************************************************************
 *
 * Free the buffer allocated by mSplit().
 *
 * char** toks = NULL;
 * int num_toks = 0;
 * toks = (str, " ", 2, &num_toks, 0);
 * mSplitFree(&toks, num_toks);
 *
 * At this point, toks is again NULL.
 *
 ****************************************************************/
void mSplitFree(char ***pbuf, int num_toks)
{
    int i;
    char** buf;  /* array of string pointers */

    if( pbuf==NULL || *pbuf==NULL )
    {
        return;
    }

    buf = *pbuf;

    for( i=0; i<num_toks; i++ )
    {
        if( buf[i] != NULL )
        {
            free( buf[i] );
            buf[i] = NULL;
        }
    }

    free(buf);
    *pbuf = NULL;
}




/****************************************************************
 *
 *  Function: mContainsSubstr(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      b_len => data buffer length
 *      pat => pattern to find
 *      p_len => length of the data in the pattern buffer
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mContainsSubstr(char *buf, int b_len, char *pat, int p_len)
{
    char *b_idx;        /* index ptr into the data buffer */
    char *p_idx;        /* index ptr into the pattern buffer */
    char *b_end;        /* ptr to the end of the data buffer */
    int m_cnt = 0;      /* number of pattern matches so far... */
#ifdef DEBUG
    unsigned long loopcnt = 0;
#endif

    /* mark the end of the strs */
    b_end = (char *) (buf + b_len);

    /* init the index ptrs */
    b_idx = buf;
    p_idx = pat;

    do
    {
#ifdef DEBUG
        loopcnt++;
#endif

        if(*p_idx == *b_idx)
        {

            if(m_cnt == (p_len - 1))
            {
		DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
					"\n%ld compares for match\n", loopcnt););
                return 1;
            }
            m_cnt++;
            b_idx++;
            p_idx++;
        }
        else
        {
            if(m_cnt == 0)
            {
                b_idx++;
            }
            else
            {
                b_idx = b_idx - (m_cnt - 1);
            }

            p_idx = pat;

            m_cnt = 0;
        }

    } while(b_idx < b_end);


    /* if we make it here we didn't find what we were looking for */
    return 0;
}




/****************************************************************
 *
 *  Function: make_skip(char *, int)
 *
 *  Purpose: Create a Boyer-Moore skip table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the skip table
 *
 ****************************************************************/
int *make_skip(char *ptrn, int plen)
{
    int *skip = (int *) malloc(256 * sizeof(int));
    int  i;

    if (skip == NULL)
        FatalPrintError("malloc");

    for ( i = 0; i < 256; i++ )
        skip[i] = plen + 1;

    while(plen != 0)
        skip[(unsigned char) *ptrn++] = plen--;

    return skip;
}



/****************************************************************
 *
 *  Function: make_shift(char *, int)
 *
 *  Purpose: Create a Boyer-Moore shift table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the shift table
 *
 ****************************************************************/
int *make_shift(char *ptrn, int plen)
{
    int *shift = (int *) malloc(plen * sizeof(int));
    int *sptr = shift + plen - 1;
    char *pptr = ptrn + plen - 1;
    char c;

    if (shift == NULL)
        FatalPrintError("malloc");

     c = ptrn[plen - 1];

    *sptr = 1;

    while(sptr-- != shift)
    {
        char *p1 = ptrn + plen - 2, *p2, *p3;

        do
        {
            while(p1 >= ptrn && *p1-- != c);

            p2 = ptrn + plen - 2;
            p3 = p1;

            while(p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr);
        }
        while(p3 >= ptrn && p2 >= pptr);

        *sptr = shift + plen - sptr + p2 - p3;

        pptr--;
    }

    return shift;
}



/****************************************************************
 *
 *  Function: mSearch(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearch(char *buf, int blen, char *ptrn, int plen, int *skip, int *shift)
{
    int b_idx = plen;

#ifdef DEBUG
    char *hexbuf;
    int cmpcnt = 0;
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,"buf: %p  blen: %d  ptrn: %p  "
                "plen: %d\n", buf, blen, ptrn, plen););

#ifdef DEBUG
    hexbuf = fasthex(buf, blen);
    DebugMessage(DEBUG_PATTERN_MATCH,"buf: %s\n", hexbuf);
    free(hexbuf);
    hexbuf = fasthex(ptrn, plen);
    DebugMessage(DEBUG_PATTERN_MATCH,"ptrn: %s\n", hexbuf);
    free(hexbuf);
    DebugMessage(DEBUG_PATTERN_MATCH,"buf: %p  blen: %d  ptrn: %p  "
                 "plen: %d\n", buf, blen, ptrn, plen);
#endif /* DEBUG */
    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while(buf[--b_idx] == ptrn[--p_idx])
        {
#ifdef DEBUG
            cmpcnt++;
#endif
            if(b_idx < 0)
                return 0;

            if(p_idx == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                            "match: compares = %d.\n", cmpcnt););

                doe_ptr = &(buf[b_idx]) + plen;

#ifdef GIDS
                detect_depth = b_idx;
#endif /* GIDS */

                return 1;
            }
        }

        skip_stride = skip[(unsigned char) buf[b_idx]];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "no match: compares = %d.\n", cmpcnt););

    return 0;
}



/****************************************************************
 *
 *  Function: mSearchCI(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring matching is case insensitive
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearchCI(char *buf, int blen, char *ptrn, int plen, int *skip, int *shift)
{
    int b_idx = plen;
#ifdef DEBUG
    int cmpcnt = 0;
#endif

    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while((unsigned char) ptrn[--p_idx] == 
                toupper((unsigned char) buf[--b_idx]))
        {
#ifdef DEBUG
            cmpcnt++;
#endif
            if(p_idx == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                            "match: compares = %d.\n", 
                            cmpcnt););
                doe_ptr = &(buf[b_idx]) + plen;
#ifdef GIDS
                detect_depth = b_idx;
#endif /* GIDS */
                return 1;
            }
        }

        skip_stride = skip[toupper((unsigned char) buf[b_idx])];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "no match: compares = %d.\n", cmpcnt););

    return 0;
}


/****************************************************************
 *
 *  Function: mSearchREG(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearchREG(char *buf, int blen, char *ptrn, int plen, int *skip, int *shift)
{
    int b_idx = plen;
    int literal = 0;
    int regexcomp = 0;
#ifdef DEBUG
    int cmpcnt = 0;
#endif /*DEBUG*/
    
    DEBUG_WRAP(
	       DebugMessage(DEBUG_PATTERN_MATCH, "buf: %p  blen: %d  ptrn: %p "
			    " plen: %d b_idx: %d\n", buf, blen, ptrn, plen, b_idx);
	       DebugMessage(DEBUG_PATTERN_MATCH, "packet data: \"%s\"\n", buf);
	       DebugMessage(DEBUG_PATTERN_MATCH, "matching for \"%s\"\n", ptrn);
	       );
	       
    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

	DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Looping... "
				"([%d]0x%X (%c) -> [%d]0x%X(%c))\n",
				b_idx, buf[b_idx-1], 
				buf[b_idx-1], 
				p_idx, ptrn[p_idx-1], ptrn[p_idx-1]););

        while(buf[--b_idx] == ptrn[--p_idx]
              || (ptrn[p_idx] == '?' && !literal)
              || (ptrn[p_idx] == '*' && !literal)
              || (ptrn[p_idx] == '\\' && !literal))
        {
	    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "comparing: b:%c -> p:%c\n", 
				    buf[b_idx], ptrn[p_idx]););
#ifdef DEBUG
            cmpcnt++;
#endif

            if(literal)
                literal = 0;
            if(!literal && ptrn[p_idx] == '\\')
                literal = 1;
            if(ptrn[p_idx] == '*')
            {
		DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,"Checking wildcard matching...\n"););
                while(p_idx != 0 && ptrn[--p_idx] == '*'); /* fool-proof */

                while(buf[--b_idx] != ptrn[p_idx])
                {
		    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "comparing: b[%d]:%c -> p[%d]:%c\n",
					    b_idx, buf[b_idx], p_idx, ptrn[p_idx]););

                   regexcomp++;
                    if(b_idx == 0)
                    {
			DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
						"b_idx went to 0, returning 0\n");)
                        return 0;
                    }
                }

		DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "got wildcard final char match! (b[%d]: %c -> p[%d]: %c\n", b_idx, buf[b_idx], p_idx, ptrn[p_idx]););
            }

            if(p_idx == 0)
            {
		DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "match: compares = %d.\n", 
					cmpcnt););
                return 1;
            }

            if(b_idx == 0)
                break;
        }

	DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "skip-shifting...\n"););
	skip_stride = skip[(unsigned char) buf[b_idx]];
	shift_stride = shift[p_idx];
	
	b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
	DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "b_idx skip-shifted to %d\n", b_idx););
	b_idx += regexcomp;
	DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
				"b_idx regex compensated %d steps, to %d\n", regexcomp, b_idx););
	regexcomp = 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "no match: compares = %d, b_idx = %d, "
			    "blen = %d\n", cmpcnt, b_idx, blen););

    return 0;
}
