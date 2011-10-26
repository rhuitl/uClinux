/* $Id$ */
/*
** Copyright (C) 2003 Brian Caswell <bmc@snort.org>
** Copyright (C) 2003 Michael J. Pomraning <mjp@securepipe.com>
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
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bounds.h"
#include "rules.h"
#include "debug.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "plugin_enum.h"
#include "util.h"
#include "mstring.h"
#include <sys/types.h>

#ifdef WIN32
#define PCRE_DEFINITION
#endif

#include <pcre.h>

extern int g_nopcre;

typedef struct _PcreData
{
    pcre *re;           /* compiled regex */
    pcre_extra *pe;     /* studied regex foo */
    int options;        /* sp_pcre specfic options (relative & inverse) */
} PcreData;


#define SNORT_PCRE_RELATIVE 1  /* relative to the end of the last match */
#define SNORT_PCRE_INVERT   2  /* invert detect */
#define SNORT_PCRE_URI      4  /* check URI buffers */
#define SNORT_PCRE_RAWBYTES 8  /* Don't use decoded buffer (if available) */

/* 
 * we need to specify the vector length for our pcre_exec call.  we only care 
 * about the first vector, which if the match is successful will include the
 * offset to the end of the full pattern match.  If we decide to store other
 * matches, make *SURE* that this is a multiple of 3 as pcre requires it.
 */
#define SNORT_PCRE_OVECTOR_SIZE 3

extern u_int8_t DecodeBuffer[DECODE_BLEN];
extern u_int8_t *doe_ptr;

void SnortPcreInit(char *, OptTreeNode *, int);
void SnortPcreParse(char *, PcreData *, OptTreeNode *);
void SnortPcreDump(PcreData *);
int SnortPcre(Packet *, struct _OptTreeNode *, OptFpList *);

void SetupPcre(void)
{
    RegisterPlugin("pcre", SnortPcreInit);
}

void SnortPcreInit(char *data, OptTreeNode *otn, int protocol)
{
    PcreData *pcre_data;
    OptFpList *fpl;

    /* 
     * allocate the data structure for pcre
     */
    pcre_data = (PcreData *) SnortAlloc(sizeof(PcreData));

    if(pcre_data == NULL)
    {
        FatalError("%s (%d): Unable to allocate pcre_data node\n",
                   file_name, file_line);
    }

    SnortPcreParse(data, pcre_data, otn);

    fpl = AddOptFuncToList(SnortPcre, otn);

    /*
     * attach it to the context node so that we can call each instance
     * individually
     */
    fpl->context = (void *) pcre_data;

    if (pcre_data->options & SNORT_PCRE_RELATIVE)
        fpl->isRelative = 1;

    return;
}

void SnortPcreParse(char *data, PcreData *pcre_data, OptTreeNode *otn)
{
    const char *error;
    char *re, *free_me;
    char *opts;
    char delimit = '/';
    int erroffset;
    int compile_flags = 0;
    
    if(data == NULL) 
    {
        FatalError("%s (%d): pcre requires a regular expression\n", 
                   file_name, file_line);
    }

    if(!(free_me = strdup(data)))
    {
        FatalError("%s (%d): pcre strdup() failed\n", file_name, file_line);
    }
    re = free_me;


    /* get rid of starting and ending whitespace */
    while (isspace((int)re[strlen(re)-1])) re[strlen(re)-1] = '\0';
    while (isspace((int)*re)) re++;

    if(*re == '!') { 
        pcre_data->options |= SNORT_PCRE_INVERT;
        re++;
        while(isspace((int)*re)) re++;
    }

    /* now we wrap the RE in double quotes.  stupid snort parser.... */
    if(*re != '"') {
        printf("It isn't \"\n");
        goto syntax;
    }
    re++;

    if(re[strlen(re)-1] != '"')
    {
        printf("It isn't \"\n");
        goto syntax;
    }
    
    /* remove the last quote from the string */
    re[strlen(re) - 1] = '\0';
    
    /* 'm//' or just '//' */
        
    if(*re == 'm')
    {
        re++;
        if(! *re) goto syntax;
        
        /* Space as a ending delimiter?  Uh, no. */
        if(isspace((int)*re)) goto syntax;
        /* using R would be bad, as it triggers RE */
        if(*re == 'R') goto syntax;   

        delimit = *re;
    } 
    else if(*re != delimit)
        goto syntax;

    /* find ending delimiter, trim delimit chars */
    opts = strrchr(re, delimit);
    if(!((opts - re) > 1)) /* empty regex(m||) or missing delim not OK */
        goto syntax;

    re++;
    *opts++ = '\0';

    /* process any /regex/ismxR options */
    while(*opts != '\0') {
        switch(*opts) {
        case 'i':  compile_flags |= PCRE_CASELESS;            break;
        case 's':  compile_flags |= PCRE_DOTALL;              break;
        case 'm':  compile_flags |= PCRE_MULTILINE;           break;
        case 'x':  compile_flags |= PCRE_EXTENDED;            break;
            
            /* 
             * these are pcre specific... don't work with perl
             */ 
        case 'A':  compile_flags |= PCRE_ANCHORED;            break;
        case 'E':  compile_flags |= PCRE_DOLLAR_ENDONLY;      break;
        case 'G':  compile_flags |= PCRE_UNGREEDY;            break;

            /*
             * these are snort specific don't work with pcre or perl
             */
        case 'R':  pcre_data->options |= SNORT_PCRE_RELATIVE; break;
        case 'U':  pcre_data->options |= SNORT_PCRE_URI;      break;
        case 'B':  pcre_data->options |= SNORT_PCRE_RAWBYTES; break;
        default:
            FatalError("%s (%d): unknown/extra pcre option encountered\n", file_name, file_line);
        }
        opts++;
    }

    if(pcre_data->options & SNORT_PCRE_RELATIVE && 
       pcre_data->options & SNORT_PCRE_URI)
        FatalError("%s(%d): PCRE unsupported configuration : both relative & uri options specified\n", file_name, file_line);

    
    /* now compile the re */
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "pcre: compiling %s\n", re););
    pcre_data->re = pcre_compile(re, compile_flags, &error, &erroffset, NULL);

    if(pcre_data->re == NULL) 
    {
        FatalError("%s(%d) : pcre compile of \"%s\" failed at offset "
                   "%d : %s\n", file_name, file_line, re, erroffset, error);
    }


    /* now study it... */
    pcre_data->pe = pcre_study(pcre_data->re, 0, &error);

    if(error != NULL) 
    {
        FatalError("%s(%d) : pcre study failed : %s\n", file_name, 
                   file_line, error);
    }

    free(free_me);

    return;

 syntax:
    if(free_me) free(free_me);

    FatalError("ERROR %s Line %d => unable to parse pcre regex %s\n", 
               file_name, file_line, data);

}

/** 
 * Perform a search of the PCRE data.
 * 
 * @param pcre_data structure that options and patterns are passed in
 * @param buf buffer to search
 * @param len size of buffer
 * @param start_offset initial offset into the buffer
 * @param found_offset pointer to an integer so that we know where the search ended
 *
 * *found_offset will be set to -1 when the find is unsucessful OR the routine is inverted
 *
 * @return 1 when we find the string, 0 when we don't (unless we've been passed a flag to invert)
 */
static int pcre_search(const PcreData *pcre_data,
                       const char *buf,
                       int len,
                       int start_offset,
                       int *found_offset)
{
    int ovector[SNORT_PCRE_OVECTOR_SIZE];
    int matched;
    int result;
  
    if(pcre_data == NULL
       || buf == NULL
       || len <= 0
       || start_offset < 0
       || start_offset >= len
       || found_offset == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Returning 0 because we didn't have the required parameters!\n"););
        return 0;
    }

    *found_offset = -1;
    
    result = pcre_exec(pcre_data->re,            /* result of pcre_compile() */
                       pcre_data->pe,            /* result of pcre_study()   */
                       buf,                      /* the subject string */
                       len,                      /* the length of the subject string */
                       start_offset,             /* start at offset 0 in the subject */
                       0,                        /* options(handled at compile time */
                       ovector,                  /* vector for substring information */
                       SNORT_PCRE_OVECTOR_SIZE); /* number of elements in the vector */

    if(result >= 0)
    {
        matched = 1;
    }
    else if(result == PCRE_ERROR_NOMATCH)
    {
        matched = 0;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "pcre_exec error : %d \n", result););
        return 0;
    }

    /* invert sense of match */
    if(pcre_data->options & SNORT_PCRE_INVERT) 
    {
        matched = !matched;
    }
    else
    {
        
        *found_offset = ovector[1];        
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Setting Doe_ptr and found_offset: %p %d\n",
                                doe_ptr, found_offset););
    }

    return matched;
}

int SnortPcre(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PcreData *pcre_data;   /* pointer to the eval string for each test */
    int found_offset;  /* where is the ending location of the pattern */
    char *base_ptr, *end_ptr, *start_ptr;
    int dsize;
    int length; /* length of the buffer pointed to by base_ptr  */
    int matched = 0;
    extern HttpUri UriBufs[URI_COUNT];
    int i;

    DEBUG_WRAP(char *hexbuf;);

    //short circuit this for testing pcre performance impact
    if( g_nopcre )
        return 0;
    
    /* get my data */
    pcre_data =(PcreData *) fp_list->context;

    /* This is the HTTP case */
    if(pcre_data->options & SNORT_PCRE_URI) 
    {
        for(i=0;i<p->uri_count;i++)
        {
            matched = pcre_search(pcre_data,
                                  UriBufs[i].uri,
                                  UriBufs[i].length,
                                  0,
                                  &found_offset);
            
            if(matched)
            {
                /* don't touch doe_ptr on URI contents */
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
        }
        
        return 0;
    }
    /* end of the HTTP case */

    if(p->packet_flags & PKT_ALT_DECODE && !(pcre_data->options & SNORT_PCRE_RAWBYTES))
    {
        dsize = p->alt_dsize;
        start_ptr = (char *) DecodeBuffer;
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "using alternative decode buffer in pcre!\n"););
    }
    else
    {
        dsize = p->dsize;
        start_ptr = (char *) p->data;
    }

    base_ptr = start_ptr;
    end_ptr = start_ptr + dsize;

    /* doe_ptr's would be set by the previous content option */
    if(pcre_data->options & SNORT_PCRE_RELATIVE && doe_ptr)
    {
        if(!inBounds(start_ptr, end_ptr, doe_ptr))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "pcre bounds check failed on a relative content match\n"););
            return 0;
        }
        
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "pcre ... checking relative offset\n"););
        base_ptr = doe_ptr;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "pcre ... checking absolute offset\n"););
        base_ptr = start_ptr;
    }

    length = end_ptr - base_ptr;
    
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                            "pcre ... base: %p start: %p end: %p doe: %p length: %d\n",
                            base_ptr, start_ptr, end_ptr, doe_ptr, length););

    DEBUG_WRAP(hexbuf = hex(base_ptr, length);
               DebugMessage(DEBUG_PATTERN_MATCH, "pcre payload: %s\n", hexbuf);
               free(hexbuf);
               );


    matched = pcre_search(pcre_data, base_ptr, length, 0, &found_offset);

    /* set the doe_ptr if we have a valid offset */
    if(found_offset > 0)
    {
        doe_ptr = (u_int8_t *) base_ptr + found_offset;
    }
    
    while(matched)
    {
        int search_offset = found_offset;
        int next_found = fp_list->next->OptTestFunc(p, otn, fp_list->next);

        if(next_found)
        {
            /* if the OTN checks are successful, return 1, else
               return the next iteration */
            /* set the doe_ptr for stateful pattern matching later */

            doe_ptr = (u_int8_t *) base_ptr + found_offset;

            return 1;
        }

        /* if the next option isn't relative and it failed, we're done */
        if (fp_list->next->isRelative == 0)
            return 0;

        /* the other OTNs search's were not successful so we need to keep searching */
        if(search_offset <= 0 || length < search_offset)
        {
            /* make sure that the search offset is reasonable */
            return 0;
        }

        matched = pcre_search(pcre_data, base_ptr, length,
                              search_offset, &found_offset);

        /* set the doe_ptr if we have a valid offset */
        if(found_offset > 0)
        {
            doe_ptr = (u_int8_t *) base_ptr + found_offset;
        }
        
        if(matched)
        {
            if(fp_list->next->OptTestFunc(p, otn, fp_list->next))
            {
                /* if the OTN checks are successful, return 1, else
                   return the next iteration */

                return 1;
            }
            
        }            
    }

    /* finally return 0 */
    return 0;
}

