/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

/* $Id$ */
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef DEBUG
#include <assert.h>
#endif

#include "sp_pattern_match.h"
#include "bounds.h"
#include "rules.h"
#include "plugbase.h"
#include "debug.h"
#include "mstring.h"
#include "util.h" 
#include "parser.h"  /* why does parser.h define Add functions.. */
#include "plugin_enum.h"
#include "checksum.h"
#include "inline.h"

#define MAX_PATTERN_SIZE 2048

static void PayloadSearchInit(char *, OptTreeNode *, int);
static void PayloadSearchListInit(char *, OptTreeNode *, int);
static void ParseContentListFile(char *, OptTreeNode *, int);
static void PayloadSearchUri(char *, OptTreeNode *, int);
static void PayloadSearchHttpBody(char *, OptTreeNode *, int);
static void PayloadSearchHttpUri(char *, OptTreeNode *, int);
static void ParsePattern(char *, OptTreeNode *, int);
static int CheckANDPatternMatch(Packet *, struct _OptTreeNode *, OptFpList *);
static int CheckORPatternMatch(Packet *, struct _OptTreeNode *, OptFpList *);
static int CheckUriPatternMatch(Packet *, struct _OptTreeNode *, OptFpList *);
static void PayloadSearchOffset(char *, OptTreeNode *, int);
static void PayloadSearchDepth(char *, OptTreeNode *, int);
static void PayloadSearchNocase(char *, OptTreeNode *, int);
static void PayloadSearchRegex(char *, OptTreeNode *, int);
static void PayloadSearchDistance(char *, OptTreeNode *, int);
static void PayloadSearchWithin(char *, OptTreeNode *, int);
static void PayloadSearchRawbytes(char *, OptTreeNode *, int);
static void PayloadReplaceInit(char *, OptTreeNode *, int);
static PatternMatchData * ParseReplacePattern(char *, OptTreeNode *);
int PayloadReplace(Packet *, struct _OptTreeNode *, OptFpList *, int
                         depth);
static int uniSearchReal(char *data, int dlen, PatternMatchData *pmd, int nocase);

static PatternMatchData * NewNode(OptTreeNode *, int);
void PayloadSearchCompile();

int list_file_line;     /* current line being processed in the list file */
int lastType = PLUGIN_PATTERN_MATCH;
u_int8_t *doe_ptr;

int detect_depth;       /* depth to the first char of the match */

extern HttpUri UriBufs[URI_COUNT]; /* the set of buffers that we are using to match against
                      set in decode.c */
extern u_int8_t DecodeBuffer[DECODE_BLEN];

extern char *file_name;
extern int file_line;


void SetupPatternMatch()
{
    RegisterPlugin("content", PayloadSearchInit);
    RegisterPlugin("content-list", PayloadSearchListInit);
    RegisterPlugin("offset", PayloadSearchOffset);
    RegisterPlugin("depth", PayloadSearchDepth);
    RegisterPlugin("nocase", PayloadSearchNocase);
    RegisterPlugin("rawbytes", PayloadSearchRawbytes);
    RegisterPlugin("regex", PayloadSearchRegex);
    RegisterPlugin("uricontent", PayloadSearchUri);
    RegisterPlugin("http_client_body", PayloadSearchHttpBody);
    RegisterPlugin("http_uri", PayloadSearchHttpUri);
    RegisterPlugin("distance", PayloadSearchDistance);
    RegisterPlugin("within", PayloadSearchWithin);
    RegisterPlugin("replace", PayloadReplaceInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "Plugin: PatternMatch Initialized!\n"););
}

void PayloadReplaceInit(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;
    PatternMatchData *test_idx;

    if(!InlineMode())
        return;
    
    idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH];

    if(idx == NULL)
    {
        FatalError("ERROR %s Line %d => Please place \"content\" rules "
                   "before depth, nocase, replace or offset modifiers.\n",
                   file_name, file_line);
    }

    test_idx = ParseReplacePattern(data, otn);
#ifdef DEBUG
    printf("idx (%p) pattern_size (%d) replace_size (%d)\n", test_idx, 
            test_idx->pattern_size, test_idx->replace_size);
#endif
    if (test_idx && test_idx->pattern_size != test_idx->replace_size)
    {
        FatalError("ERROR %s Line %d => The length of the replacement "
                   "string must be the same length as the content string.\n",
                   file_name, file_line);
    }

#ifdef DEBUG
    printf("PayLoadReplaceInit Added to rule!\n");
#endif
}

/*************************************************************************/
/*                                                                       */
/*  Sigh.... this should be part of ParsePattern, but that can wait      */
/*                                                                       */
/*************************************************************************/

PatternMatchData * ParseReplacePattern(char *rule, OptTreeNode * otn)
{
    unsigned char tmp_buf[MAX_PATTERN_SIZE];

    /* got enough ptrs for you? */
    char *start_ptr;
    char *end_ptr;
    char *idx;
    char *dummy_idx;
    char *dummy_end;
    char hex_buf[3];
    u_int dummy_size = 0;
    int size;
    int hexmode = 0;
    int hexsize = 0;
    int pending = 0;
    int cnt = 0;
    int literal = 0;
    int exception_flag = 0;
    PatternMatchData *ds_idx;
    int ret;

    /* clear out the temp buffer */
    bzero(tmp_buf, MAX_PATTERN_SIZE);

    while(isspace((int)*rule))
        rule++;

    if(*rule == '!')
    {
        exception_flag = 1;
    }

    /* find the start of the data */
    start_ptr = index(rule, '"');

    if(start_ptr == NULL)
    {
        FatalError("ERROR %s Line %d => Replace data needs to be "
                   "enclosed in quotation marks (\")!\n",
                   file_name, file_line);
    }

    /* move the start up from the beggining quotes */
    start_ptr++;

    /* find the end of the data */
    end_ptr = strrchr(start_ptr, '"');

    if(end_ptr == NULL)
    {
        FatalError("ERROR %s Line %d => Replace data needs to be enclosed "
                   "in quotation marks (\")!\n", file_name, file_line);
    }

    /* set the end to be NULL */
    *end_ptr = '\0';

    /* how big is it?? */
    size = end_ptr - start_ptr;

    /* uh, this shouldn't happen */
    if(size <= 0)
    {
        FatalError("ERROR %s Line %d => Bad pattern length!\n",
                   file_name, file_line);
    }
    /* set all the pointers to the appropriate places... */
    idx = start_ptr;

    /* set the indexes into the temp buffer */
    dummy_idx = tmp_buf;
    dummy_end = (dummy_idx + size);

    /* why is this buffer so small? */
    bzero(hex_buf, 3);
    memset(hex_buf, '0', 2);

    /* BEGIN BAD JUJU..... */
    while(idx < end_ptr)
    {
        if (dummy_size >= MAX_PATTERN_SIZE-1)
        {
            /* Have more data to parse and pattern is about to go beyond end of buffer */
            FatalError("ParsePattern() dummy "
                    "buffer overflow, make a smaller "
                    "pattern please! (Max size = %d)\n", MAX_PATTERN_SIZE-1);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "processing char: %c\n", *idx););

        switch(*idx)
        {
            case '|':
            
                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got bar... "););
        
                if(!literal)
                {
            
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
                        "not in literal mode... "););
            
                    if(!hexmode)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "Entering hexmode\n"););

                        hexmode = 1;
                    }
                    else
                    {
                
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "Exiting hexmode\n"););
            
                        hexmode = 0;
                        pending = 0;
                    }

                    if(hexmode)
                        hexsize = 0;
                }
                else
                {

                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "literal set, Clearing\n"););

                    literal = 0;
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    dummy_size++;
                }

                break;

            case '\\':
        
                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got literal char... "););

                if(!literal)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "Setting literal\n"););
            
                    literal = 1;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                        "Clearing literal\n"););
            
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    literal = 0;
                    dummy_size++;
                }
                break;

            default:
                if(hexmode)
                {
                    if(isxdigit((int) *idx))
                    {
                        hexsize++;

                        if(!pending)
                        {
                            hex_buf[0] = *idx;
                            pending++;
                        }
                        else
                        {
                            hex_buf[1] = *idx;
                            pending--;

                            if(dummy_idx < dummy_end)
                            {
                                tmp_buf[dummy_size] = (u_char)
                                    strtol(hex_buf, (char **) NULL, 16)&0xFF;

                                dummy_size++;
                                bzero(hex_buf, 3);
                                memset(hex_buf, '0', 2);
                            }
                            else
                            {
                                FatalError("ERROR => ParsePattern() dummy "
                                           "buffer overflow, make a smaller "
                                           "pattern please! (Max size = %d)\n", MAX_PATTERN_SIZE-1);
                            }
                        }
                    }
                    else
                    {
                        if(*idx != ' ')
                        {
                            FatalError("ERROR Line %d => What is this "
                                       "\"%c\"(0x%X) doing in your binary "
                                       "buffer? Valid hex values only please! "
                                       "(0x0 -0xF) Position: %d\n",
                                       file_line, (char) *idx, (char) *idx, cnt);
                        }
                    }
                }
                else
                {
                    if(*idx >= 0x1F && *idx <= 0x7e)
                    {
                        if(dummy_idx < dummy_end)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;
                        }
                        else
                        {
                            FatalError("ERROR Line %d=> ParsePattern() dummy "
                                       "buffer overflow!\n", file_line);
                        }

                        if(literal)
                        {
                            literal = 0;
                        }
                    }
                    else
                    {
                        if(literal)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;
                
                            DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                            "Clearing literal\n"););
                
                            literal = 0;
                        }
                        else
                        {
                            FatalError("%s(%d)=> character value out "
                                       "of range, only hex characters allowed in binary content buffers\n",
                                       file_name, file_line);
                        }
                    }
                }

                break;

        } /* end switch */

        dummy_idx++;
        idx++;
        cnt++;
    }
    /* ...END BAD JUJU */

    /* error prunning */

    if (literal) {
        FatalError("%s(%d)=> backslash escape is not "
           "completed\n", file_name, file_line);
    }
    if (hexmode) {
        FatalError("%s(%d)=> hexmode is not "
           "completed\n", file_name, file_line);
    }
    ds_idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH];

    while(ds_idx->next != NULL)
        ds_idx = ds_idx->next;

    if((ds_idx->replace_buf = (char *) calloc(dummy_size+1,
                                                  sizeof(char))) == NULL)
    {
        FatalError("ERROR => ParsePattern() pattern_buf malloc filed!\n");
    }

    //memcpy(ds_idx->replace_buf, tmp_buf, dummy_size);
    ret = SafeMemcpy(ds_idx->replace_buf, tmp_buf, dummy_size, 
                     ds_idx->replace_buf, (ds_idx->replace_buf+dummy_size));

    if (ret == SAFEMEM_ERROR)
    {
        FatalError("ERROR %s Line %d => SafeMemcpy failed\n", file_name, file_line);
    }

    ds_idx->replace_size = dummy_size;

    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, 
                "ds_idx (%p) replace_size(%d) replace_buf(%s)\n", ds_idx,
                ds_idx->replace_size, ds_idx->replace_buf););

    return ds_idx;
}

int PayloadReplace(Packet *p, struct _OptTreeNode *otn,
                         OptFpList *fp_list, int depth)
{
    struct pseudoheader
    {
        u_int32_t sip, dip;
        u_int8_t zero;
        u_int8_t protocol;
        u_int16_t len;
    };

    PatternMatchData *idx;
    struct pseudoheader ph;
    unsigned int ip_len;
    unsigned int hlen;
    int ret;

    //idx = (PatternMatchData *)otn->ds_list[PLUGIN_PATTERN_MATCH];
    idx = (PatternMatchData *)fp_list->context;

    if (depth >= 0)
    {
        //memcpy(p->data+depth, idx->replace_buf, strlen(idx->replace_buf));
        ret = SafeMemcpy( (p->data + depth), idx->replace_buf, strlen(idx->replace_buf), 
                          p->data, (p->data + p->dsize) );

        if (ret == SAFEMEM_ERROR)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "PayloadReplace() => SafeMemcpy() failed\n"););
            return 0;
        }

#ifdef GIDS
        InlineReplace();
#endif

        /* calculate new checksum */
        p->iph->ip_csum=0;
        hlen = IP_HLEN(p->iph) << 2;
        ip_len=ntohs(p->iph->ip_len);
        ip_len -= hlen;
        p->iph->ip_csum = in_chksum_ip((u_short *)p->iph, hlen);

        if (p->tcph)
        {
            p->tcph->th_sum = 0;
            ph.sip = (u_int32_t)(p->iph->ip_src.s_addr);
            ph.dip = (u_int32_t)(p->iph->ip_dst.s_addr);
            ph.zero = 0;
            ph.protocol = p->iph->ip_proto;
            ph.len = htons((u_short)ip_len);
            p->tcph->th_sum = in_chksum_tcp((u_short *)&ph,
                                            (u_short *)(p->tcph), ip_len);
        }
        else if (p->udph)
        {
            p->udph->uh_chk = 0;
            ph.sip = (u_int32_t)(p->iph->ip_src.s_addr);
            ph.dip = (u_int32_t)(p->iph->ip_dst.s_addr);
            ph.zero = 0;
            ph.protocol = p->iph->ip_proto;
            ph.len = htons((u_short)ip_len);
            p->udph->uh_chk = in_chksum_udp((u_short *)&ph,
                                            (u_short *)(p->udph), ip_len);
        }
        else if (p->icmph)
        {
            p->icmph->csum = 0;
            ph.sip = (u_int32_t)(p->iph->ip_src.s_addr);
            ph.dip = (u_int32_t)(p->iph->ip_dst.s_addr);
            ph.zero = 0;
            ph.protocol = p->iph->ip_proto;
            ph.len = htons((u_short)ip_len);
            p->icmph->csum = in_chksum_icmp((u_int16_t *)(p->icmph), ip_len);
        }
    }

    return 1;
}

static inline int computeDepth(int dlen, PatternMatchData * pmd) 
{
    /* do some tests to make sure we stay in bounds */
    if((pmd->depth + pmd->offset) > dlen)
    {
        /* we want to check only depth bytes anyway */
        int sub_depth = dlen - pmd->offset; 

        if((sub_depth > 0) && (sub_depth >= (int)pmd->pattern_size))
        {
            return  sub_depth;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                        "Pattern Match failed -- sub_depth: %d < "
                        "(int)pmd->pattern_size: %d!\n",
                        sub_depth, (int)pmd->pattern_size););

            return -1;
        }
    }
    else
    {      
        if(pmd->depth && (dlen - pmd->offset > pmd->depth))
        {
            return pmd->depth;
        }
        else
        {
            return dlen - pmd->offset;
        }
    }
}

/*
 * Figure out how deep the into the packet from the base_ptr we can go
 *
 * base_ptr = the offset into the payload relative to the last match plus the offset
 *            contained within the current pmd
 *
 * dlen = amount of data in the packet from the base_ptr to the end of the packet
 *
 * pmd = the patterm match data struct for this test
 */
static inline int computeWithin(int dlen, PatternMatchData *pmd)
{
    /* do we want to check more bytes than there are in the buffer? */
    if(pmd->within > dlen)
    {
        /* should we just return -1 here since the data might actually be within 
         * the stream but not the current packet's payload?
         */
        
        /* if the buffer size is greater than the size of the pattern to match */
        if(dlen >= (int)pmd->pattern_size)
        {
            /* return the size of the buffer */
            return dlen;
        }
        else
        {
            /* failed, pattern size is greater than number of bytes in the buffer */
            return -1;
        }
    }

    /* the within vaule is in range of the number of buffer bytes */
    return pmd->within;
}


static int uniSearchREG(char * data, int dlen, PatternMatchData * pmd)
{
    int depth = computeDepth(dlen, pmd);
    /* int distance_adjustment = 0;
     *  int depth_adjustment = 0;
     */
    int success = 0;

    if (depth < 0)
        return 0;

    /* XXX DESTROY ME */
    /*success =  mSearchREG(data + pmd->offset + distance_adjustment, 
            depth_adjustment!=0?depth_adjustment:depth, 
            pmd->pattern_buf, pmd->pattern_size, pmd->skip_stride, 
            pmd->shift_stride);*/

    return success;
}



/* 
 * case sensitive search
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated 
 *        against offset + depth before function entry (not distance/within)
 * pmd = pointer to pattern match data struct
 */

static int uniSearch(char *data, int dlen, PatternMatchData *pmd)
{
    return uniSearchReal(data, dlen, pmd, 0);
}

/* 
 * case insensitive search
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated 
 *        against offset + depth before function entry (not distance/within)
 * pmd = pointer to pattern match data struct
 */
static int uniSearchCI(char *data, int dlen, PatternMatchData *pmd)
{
    return uniSearchReal(data, dlen, pmd, 1);
}


/* 
 * single search function. 
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated 
 *        against offset + depth before function entry (not distance/within)
 * pmd = pointer to pattern match data struct
 * nocase = 0 means case sensitve, 1 means case insensitive
 *
 * return  1 for found
 * return  0 for not found
 * return -1 for error (search out of bounds)
 */       
static int uniSearchReal(char *data, int dlen, PatternMatchData *pmd, int nocase)
{
    /* 
     * in theory computeDepth doesn't need to be called because the 
     * depth + offset adjustments have been made by the calling function
     */
    int depth = dlen;
    int old_depth = dlen;
    int success = 0;
    char *start_ptr = data;
    char *end_ptr = data + dlen;
    char *base_ptr = start_ptr;
    
    DEBUG_WRAP(char *hexbuf;);


    if(pmd->use_doe != 1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "NOT Using Doe Ptr\n"););
        doe_ptr = NULL; /* get rid of all our pattern match state */
    }

    /* check to see if we've got a stateful start point */
    if(doe_ptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Using Doe Ptr\n"););

        base_ptr = doe_ptr;
        depth = dlen - ((char *) doe_ptr - data);
    }
    else
    {
        base_ptr = start_ptr;
        depth = dlen;
    }

    /* if we're using a distance call */
    if(pmd->distance)
    {
        /* set the base pointer up for the distance */
        base_ptr += pmd->distance;
        depth -= pmd->distance;
    }
    else /* otherwise just use the offset (validated by calling function) */
    {
        base_ptr += pmd->offset;
        depth -= pmd->offset;
    }
    
    if(pmd->within != 0)
    {
        /* 
         * calculate the "real" depth based on the current base and available
         * number of bytes in the buffer
         *
         * this should account for the current base_ptr as it relates to 
         * the back of the buffer being tested
         */
        old_depth = depth;
        
        depth = computeWithin(depth, pmd);
        
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Changing Depth from %d to %d\n", old_depth, depth););
    }

    /* make sure we and in range */
    if(!inBounds(start_ptr, end_ptr, base_ptr))
    {
        
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "returning because base_ptr"
                                " is out of bounds start_ptr: %p end: %p base: %p\n",
                                start_ptr, end_ptr, base_ptr););
        return -1;
    }

    if(depth < 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "returning because depth is negative (%d)\n",
                                depth););
        return -1;        
    }

    if(depth > dlen)
    {
        /* if offsets are negative but somehow before the start of the
           packet, let's make sure that we get everything going
           straight */
        depth = dlen;
    }

    if((pmd->depth > 0) && (depth > pmd->depth))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Setting new depth to %d from %d\n",
                                pmd->depth, depth););

        depth = pmd->depth;
    }
    
    /* make sure we end in range */
    if(!inBounds(start_ptr, end_ptr, base_ptr + depth - 1))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "returning because base_ptr + depth - 1"
                                " is out of bounds start_ptr: %p end: %p base: %p\n",
                                start_ptr, end_ptr, base_ptr););
        return 0;
    }

#ifdef DEBUG
    assert(depth <= old_depth);

    DebugMessage(DEBUG_PATTERN_MATCH, "uniSearchReal:\n ");

    hexbuf = hex(pmd->pattern_buf, pmd->pattern_size);
    DebugMessage(DEBUG_PATTERN_MATCH, "   p->data: %p\n   doe_ptr: %p\n   "
                 "base_ptr: %p\n   depth: %d\n   searching for: %s\n", 
                 data, doe_ptr, base_ptr, depth, hexbuf);
    free(hexbuf);
#endif /* DEBUG */
    
    if(nocase)
    {
        success = mSearchCI(base_ptr, depth, 
                            pmd->pattern_buf,
                            pmd->pattern_size,
                            pmd->skip_stride, 
                            pmd->shift_stride);
    }
    else
    {
        success = mSearch(base_ptr, depth,
                          pmd->pattern_buf,
                          pmd->pattern_size,
                          pmd->skip_stride,
                          pmd->shift_stride);
    }


#ifdef DEBUG
    if(success)
    {
        DebugMessage(DEBUG_PATTERN_MATCH, "matched, doe_ptr: %p (%d)\n", 
                     doe_ptr, ((char *)doe_ptr - data));
    }
#endif

    return success;
}


static void make_precomp(PatternMatchData * idx)
{
    if(idx->skip_stride)
       free(idx->skip_stride);
    if(idx->shift_stride)
       free(idx->shift_stride);

    idx->skip_stride = make_skip(idx->pattern_buf, idx->pattern_size);

    idx->shift_stride = make_shift(idx->pattern_buf, idx->pattern_size);
}

void PayloadSearchListInit(char *data, OptTreeNode * otn, int protocol)
{
    char *sptr;
    char *eptr;

    lastType = PLUGIN_PATTERN_MATCH_OR;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "In PayloadSearchListInit()\n"););

    /* get the path/file name from the data */
    while(isspace((int) *data))
        data++;

    /* grab everything between the starting " and the end one */
    sptr = index(data, '"');
    eptr = strrchr(data, '"');

    if(sptr != NULL && eptr != NULL)
    {
        /* increment past the first quote */
        sptr++;

        /* zero out the second one */
        *eptr = 0;
    }
    else
    {
        sptr = data;
    }

    /* read the content keywords from the list file */
    ParseContentListFile(sptr, otn, protocol);

    /* link the plugin function in to the current OTN */
    AddOptFuncToList(CheckORPatternMatch, otn);

    return;
}


void PayloadSearchInit(char *data, OptTreeNode * otn, int protocol)
{
    OptFpList *fpl;
    PatternMatchData *pmd;

    lastType = PLUGIN_PATTERN_MATCH;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "In PayloadSearchInit()\n"););

    /* whack a new node onto the list */
    pmd = NewNode(otn, PLUGIN_PATTERN_MATCH);
    
    /* set up the pattern buffer */
    ParsePattern(data, otn, PLUGIN_PATTERN_MATCH);

    /* link the plugin function in to the current OTN */
    fpl = AddOptFuncToList(CheckANDPatternMatch, otn);

    fpl->context = pmd;
    pmd->fpl = fpl;

    if(pmd->use_doe == 1)
        fpl->isRelative = 1;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "OTN function PatternMatch Added to rule!\n"););
}



void PayloadSearchUri(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData * pmd;
    OptFpList *fpl;

    lastType = PLUGIN_PATTERN_MATCH_URI;
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "In PayloadSearchUri()\n"););

    /* whack a new node onto the list */
    pmd = NewNode(otn, PLUGIN_PATTERN_MATCH_URI);

    /* set up the pattern buffer */
    ParsePattern(data, otn, PLUGIN_PATTERN_MATCH_URI);

    pmd->uri_buffer = HTTP_BUFFER_URI;

#ifdef PATTERN_FAST
    pmd->search = uniSearch;
    make_precomp(pmd);
#endif

    /* link the plugin function in to the current OTN */
    fpl = AddOptFuncToList(CheckUriPatternMatch, otn);

    fpl->context = pmd;
    pmd->fpl = fpl;

    if(pmd->use_doe == 1)
        fpl->isRelative = 1;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "OTN function PatternMatch Added to rule!\n"););
}


void PayloadSearchHttpBody(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx = NULL;
    PatternMatchData *uriidx = NULL, *previdx = NULL;

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("(%s)%d => Please place \"content\" rules before"
           " http_client_body modifier.\n", file_name, file_line);
    }
    while(idx->next != NULL)
    {
        previdx = idx;
        idx = idx->next;
    }

    if (lastType != PLUGIN_PATTERN_MATCH_URI)
    {
        /* Need to move this PatternMatchData structure to the
         * PLUGIN_PATTERN_MATCH_URI */
        
        /* Remove it from the tail of the old list */
        if (previdx)
        {
            previdx->next = idx->next;
        }
        if (idx)
        {
            idx->next = NULL;
        }

        uriidx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH_URI];

        if (uriidx)
        {
            /* There are some uri/post patterns in this rule already */
            while (uriidx->next != NULL)
            {
                uriidx = uriidx->next;
            }
            uriidx->next = idx;
        }
        else
        {
            /* This is the first uri/post patterns in this rule */
            otn->ds_list[PLUGIN_PATTERN_MATCH_URI] = idx;
        }
        lastType = PLUGIN_PATTERN_MATCH_URI;
        idx->fpl->OptTestFunc = CheckUriPatternMatch;
    }

    idx->uri_buffer = HTTP_BUFFER_CLIENT_BODY;

    if (idx->rawbytes == 1)
    {
        FatalError("(%s)%d => Cannot use 'rawbytes' and 'http_client_body'"
            " as modifiers for the same \"content\".\n", file_name, file_line);
    }

    return;
}


void PayloadSearchHttpUri(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx = NULL;
    PatternMatchData *uriidx = NULL, *previdx = NULL;

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("(%s)%d => Please place \"content\" rules before"
           " http_uri offset modifiers.\n", file_name, file_line);
    }
    while(idx->next != NULL)
    {
        previdx = idx;
        idx = idx->next;
    }

    if (lastType != PLUGIN_PATTERN_MATCH_URI)
    {
        /* Need to move this PatternMatchData structure to the
         * PLUGIN_PATTERN_MATCH_URI */
        
        /* Remove it from the tail of the old list */
        if (previdx)
        {
            previdx->next = idx->next;
        }
        if (idx)
        {
            idx->next = NULL;
        }

        uriidx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH_URI];

        if (uriidx)
        {
            /* There are some uri/post patterns in this rule already */
            while (uriidx->next != NULL)
            {
                uriidx = uriidx->next;
            }
            uriidx->next = idx;
        }
        else
        {
            /* This is the first uri/post patterns in this rule */
            otn->ds_list[PLUGIN_PATTERN_MATCH_URI] = idx;
        }
        lastType = PLUGIN_PATTERN_MATCH_URI;
        idx->fpl->OptTestFunc = CheckUriPatternMatch;
    }

    idx->uri_buffer = HTTP_BUFFER_URI;

    if (idx->rawbytes == 1)
    {
        FatalError("(%s)%d => Cannot use 'rawbytes' and 'http_uri'"
            " as modifiers for the same \"content\".\n", file_name, file_line);
    }

    return;
}

void PayloadSearchOffset(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "In PayloadSearch()\n"););

    idx = otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("%s(%d) => Please place \"content\" rules before "
                "depth, nocase or offset modifiers.\n", file_name, file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;

    while(isspace((int) *data))
        data++;

    errno = 0;
    
    idx->offset = strtol(data, NULL, 10);

    if(errno == ERANGE)
    {
        FatalError("ERROR %s Line %d => Range problem on offset value\n", 
                file_name, file_line);
    }

    if(idx->offset > 65535 || idx->offset < -65535)
    {
        FatalError("ERROR %s Line %d => Offset greater than max Ipv4 "
                "packet size\n", file_name, file_line);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Pattern offset = %d\n", 
                idx->offset););

    return;
}



void PayloadSearchDepth(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("ERROR %s Line %d => Please place \"content\" rules "
                "before depth, nocase or offset modifiers.\n", 
                file_name, file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;

    while(isspace((int) *data))
        data++;

    errno = 0;
    
    idx->depth = strtol(data, NULL, 10);

    if(errno == ERANGE)
    {
        FatalError("ERROR %s Line %d => Range problem on depth value\n", 
                file_name, file_line);
    }

    if(idx->depth > 65535 || idx->depth < -65535)
    {
        FatalError("ERROR %s Line %d => Depth greater than max Ipv4 "
                "packet size\n", file_name, file_line);
    }

    /* check to make sure that this the depth allows this rule to fire */
    if(idx->depth != 0 && idx->depth < (int)idx->pattern_size)
    {
        FatalError("%s(%d) => The depth(%d) is less than the size of the content(%u)!\n",
                   file_name, file_line, idx->depth, idx->pattern_size);
    }


    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern depth = %d\n", 
                idx->depth););

    return;
}

void PayloadSearchNocase(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;
    int i;

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("(%s)%d => Please place \"content\" rules before"
           " depth, nocase or offset modifiers.\n", file_name, file_line);
    }
    while(idx->next != NULL)
        idx = idx->next;

    i = idx->pattern_size;

    while(--i >= 0)
        idx->pattern_buf[i] = toupper((unsigned char) idx->pattern_buf[i]);

    idx->nocase = 1;

#ifdef PATTERN_FAST
    idx->search = setSearch;
#else
    idx->search = uniSearchCI;
    make_precomp(idx);
#endif


    return;
}

void PayloadSearchRawbytes(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("ERROR Line %d => Please place \"content\" rules before"
                " rawbytes, depth, nocase or offset modifiers.\n", file_line);
    }
    while(idx->next != NULL)
        idx = idx->next;

    /* mark this as inspecting a raw pattern match rather than a
       decoded application buffer */
    idx->rawbytes = 1;    

    if (lastType == PLUGIN_PATTERN_MATCH_URI)
    {
        FatalError("(%s)%d => Cannot use 'rawbytes' and '%s' as modifiers for "
            "the same \"content\" nor use 'rawbytes' with \"uricontent\".\n",
            file_name, file_line,
            idx->uri_buffer == HTTP_BUFFER_CLIENT_BODY ?
                "http_client_body" : "http_uri" );
    }

    return;
}

void PayloadSearchDistance(char *data, OptTreeNode *otn, int protocol)
{
    PatternMatchData *idx;

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("Error %s(%d) => Distance without context, please place "
                "\"content\" keywords before distance modifiers\n", file_name,
                file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;

    while(isspace((int) *data))
        data++;


    errno = 0;
    
    idx->distance = strtol(data, NULL, 10);

    if(errno == ERANGE)
    {
        FatalError("ERROR %s Line %d => Range problem on distance value\n", 
                file_name, file_line);
    }

    if(idx->distance > 65535 || idx->distance < -65535)
    {
        FatalError("ERROR %s Line %d => Distance greater than max Ipv4 "
                "packet size\n", file_name, file_line);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern distance = %d\n", 
                idx->distance););


    if(!SetUseDoePtr(otn))
    {
        FatalError("%s Line %d => Unable to initialize doe_ptr\n",
                   file_name, file_line);
    }

    if (idx->use_doe)
    {
        idx->fpl->isRelative = 1;
    }
    
    return;
}


void PayloadSearchWithin(char *data, OptTreeNode *otn, int protocol)
{
    PatternMatchData *idx;

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("Error %s(%d) => Distance without context, please place "
                "\"content\" keywords before distance modifiers\n", file_name,
                file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;

    while(isspace((int) *data))
        data++;

    errno = 0;
    
    idx->within = strtol(data, NULL, 10);
    
    if(errno == ERANGE)
    {
        FatalError("ERROR %s Line %d => Range problem on within value\n", 
                file_name, file_line);
    }

    if(idx->within > 65535 || idx->within < -65535)
    {
        FatalError("ERROR %s Line %d => Within greater than max Ipv4 "
                "packet size\n", file_name, file_line);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern within = %d\n", 
                idx->within););

    
    if(!SetUseDoePtr(otn))
    {
        FatalError("%s Line %d => Unable to initialize doe_ptr\n",
                   file_name, file_line);
    }

    if (idx->use_doe)
    {
        idx->fpl->isRelative = 1;
    }
    
    return;
}



void PayloadSearchRegex(char *data, OptTreeNode * otn, int protocol)
{
    PatternMatchData *idx;
    int i;

    FatalError("%s(%d) => Sorry, regex isn't supported at this time. "
               "This isn't new.", file_name,file_line);

    idx = (PatternMatchData *) otn->ds_list[lastType];

    if(idx == NULL)
    {
        FatalError("%s(%d) => Please place \"content\" rules "
                   "before regex modifiers.\n", file_name, file_line);
    }

    while(idx->next != NULL)
        idx = idx->next;

    idx->search = uniSearchREG;

    i = idx->pattern_size;

    make_precomp(idx);

    return;
}




static PatternMatchData * NewNode(OptTreeNode * otn, int type)
{
    PatternMatchData *idx;

    idx = (PatternMatchData *) otn->ds_list[type];

    if(idx == NULL)
    {
        if((otn->ds_list[type] = 
                    (PatternMatchData *) calloc(sizeof(PatternMatchData), 
                                                sizeof(char))) == NULL)
        {
            FatalError("sp_pattern_match NewNode() calloc failed!\n");
        }
        
        return otn->ds_list[type];
    }
    else
    {
        idx = otn->ds_list[type];

        while(idx->next != NULL)
            idx = idx->next;

        if((idx->next = (PatternMatchData *) 
                    calloc(sizeof(PatternMatchData), sizeof(char))) == NULL)
        {
            FatalError("sp_pattern_match NewNode() calloc failed!\n");
        }

        return idx->next;
    }
}

/* This is an exported function that sets
 * PatternMatchData->use_doe so that when 
 *
 * distance, within, byte_jump, byte_test are used, they can make the
 * pattern matching functions "keep state" WRT the current packet.
 */
int SetUseDoePtr(OptTreeNode * otn)
{
    PatternMatchData *idx;

    idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH];

    if(idx == NULL)
    {
/* Visual C++ 6.0 is -supposed- to have a __FUNCTION__, however
 * it was just causing compile errors here.  So, hack around it.
 */
#ifdef WIN32
#define __FUNCTION__ "SetUseDoePtr"
#endif
        LogMessage("%s: No pattern match data found\n", __FUNCTION__);
#ifdef WIN32
#undef __FUNCTION__
#endif

        return 0;
    }
    else
    {
        /* Walk the linked list of content checks */
        while(idx->next != NULL)
        {
            idx = idx->next;
        }

        idx->use_doe = 1;
        return 1;
    }
}


/****************************************************************************
 *
 * Function: GetMaxJumpSize(char *, int)
 *
 * Purpose: Find the maximum number of characters we can jump ahead
 *          from the current offset when checking for this pattern again.
 *
 * Arguments: data => the pattern string
 *            data_len => length of pattern string
 *
 * Returns: int => number of bytes before pattern repeats within itself
 *
 ***************************************************************************/
static unsigned int GetMaxJumpSize(char *data, int data_len)
{
    int i, j;
    
    j = 0;
    for ( i = 1; i < data_len; i++ )
    {
        if ( data[j] != data[i] )
        {
            j = 0;
            continue;
        }
        if ( i == (data_len - 1) )
        {
            return (data_len - j - 1);
        }
        j++;
    }
    return data_len;
}


/****************************************************************************
 *
 * Function: ParsePattern(char *)
 *
 * Purpose: Process the application layer patterns and attach them to the
 *          appropriate rule.  My god this is ugly code.
 *
 * Arguments: rule => the pattern string
 *
 * Returns: void function
 *
 ***************************************************************************/
static void ParsePattern(char *rule, OptTreeNode * otn, int type)
{
    unsigned char tmp_buf[MAX_PATTERN_SIZE];

    /* got enough ptrs for you? */
    char *start_ptr;
    char *end_ptr;
    char *idx;
    char *dummy_idx;
    char *dummy_end;
    char *tmp;
    char hex_buf[3];
    u_int dummy_size = 0;
    int size;
    int hexmode = 0;
    int hexsize = 0;
    int pending = 0;
    int cnt = 0;
    int literal = 0;
    int exception_flag = 0;
    PatternMatchData *ds_idx;

    /* clear out the temp buffer */
    bzero(tmp_buf, MAX_PATTERN_SIZE);

    if(rule == NULL)
    {
        FatalError("%s(%d) => ParsePattern Got Null "
           "enclosed in quotation marks (\")!\n", 
           file_name, file_line);
    }

    while(isspace((int)*rule))
        rule++;

    if(*rule == '!')
    {
        exception_flag = 1;
    }

    /* find the start of the data */
    start_ptr = index(rule, '"');

    if(start_ptr == NULL)
    {
        FatalError("%s(%d) => Content data needs to be "
           "enclosed in quotation marks (\")!\n", 
           file_name, file_line);
    }

    /* move the start up from the beggining quotes */
    start_ptr++;

    /* find the end of the data */
    end_ptr = strrchr(start_ptr, '"');

    if(end_ptr == NULL)
    {
        FatalError("%s(%d) => Content data needs to be enclosed "
                   "in quotation marks (\")!\n", file_name, file_line);
    }

    /* Move the null termination up a bit more */
    *end_ptr = '\0';

    /* Is there anything other than whitespace after the trailing
     * double quote? */
    tmp = end_ptr + 1;
    while (*tmp != '\0' && isspace ((int)*tmp))
        tmp++;

    if (strlen (tmp) > 0)
    {
        FatalError("%s(%d) => Bad data (possibly due to missing semicolon) "
                   "after trailing double quote.",
                   file_name, file_line, end_ptr + 1);
    }

    /* how big is it?? */
    size = end_ptr - start_ptr;

    /* uh, this shouldn't happen */
    if(size <= 0)
    {
        FatalError("%s(%d) => Bad pattern length!\n", 
                   file_name, file_line);
    }
    /* set all the pointers to the appropriate places... */
    idx = start_ptr;

    /* set the indexes into the temp buffer */
    dummy_idx = tmp_buf;
    dummy_end = (dummy_idx + size);

    /* why is this buffer so small? */
    bzero(hex_buf, 3);
    memset(hex_buf, '0', 2);

    /* BEGIN BAD JUJU..... */
    while(idx < end_ptr)
    {
        if (dummy_size >= MAX_PATTERN_SIZE-1)
        {
            /* Have more data to parse and pattern is about to go beyond end of buffer */
            FatalError("ParsePattern() dummy "
                    "buffer overflow, make a smaller "
                    "pattern please! (Max size = %d)\n", MAX_PATTERN_SIZE-1);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "processing char: %c\n", *idx););
        switch(*idx)
        {
            case '|':
                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got bar... "););
                if(!literal)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "not in literal mode... "););
                    if(!hexmode)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Entering hexmode\n"););
                        hexmode = 1;
                    }
                    else
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Exiting hexmode\n"););

                        /*
                        **  Hexmode is not even.
                        */
                        if(!hexsize || hexsize % 2)
                        {
                            FatalError("%s(%d) => Content hexmode argument has invalid "
                                       "number of hex digits.  The argument '%s' must "
                                       "contain a full even byte string.\n",
                                       file_name, file_line, start_ptr);
                        }

                        hexmode = 0;
                        pending = 0;
                    }

                    if(hexmode)
                        hexsize = 0;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "literal set, Clearing\n"););
                    literal = 0;
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    dummy_size++;
                }

                break;

            case '\\':
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Got literal char... "););

                if(!literal)
                {
                    /* Make sure the next char makes this a valid
                     * escape sequence.
                     */
                    if (idx [1] != '\0' && strchr ("\\\":;", idx [1]) == NULL)
                    {
                        FatalError("%s(%d) => bad escape sequence starting "
                                   "with \"%s\". ", file_name, file_line, idx);
                    }

                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Setting literal\n"););

                    literal = 1;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Clearing literal\n"););
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    literal = 0;
                    dummy_size++;
                }

                break;
            case '"':
                if (!literal) {
                    FatalError("%s(%d) => Non-escaped "
                            " '\"' character!\n", file_name, file_line);
                }
                /* otherwise process the character as default */
            default:
                if(hexmode)
                {
                    if(isxdigit((int) *idx))
                    {
                        hexsize++;

                        if(!pending)
                        {
                            hex_buf[0] = *idx;
                            pending++;
                        }
                        else
                        {
                            hex_buf[1] = *idx;
                            pending--;

                            if(dummy_idx < dummy_end)
                            {                            
                                tmp_buf[dummy_size] = (u_char) 
                                    strtol(hex_buf, (char **) NULL, 16)&0xFF;

                                dummy_size++;
                                bzero(hex_buf, 3);
                                memset(hex_buf, '0', 2);
                            }
                            else
                            {
                                FatalError("ParsePattern() dummy "
                                        "buffer overflow, make a smaller "
                                        "pattern please! (Max size = %d)\n", MAX_PATTERN_SIZE-1);
                            }
                        }
                    }
                    else
                    {
                        if(*idx != ' ')
                        {
                            FatalError("%s(%d) => What is this "
                                    "\"%c\"(0x%X) doing in your binary "
                                    "buffer?  Valid hex values only please! "
                                    "(0x0 - 0xF) Position: %d\n",
                                    file_name, 
                                    file_line, (char) *idx, (char) *idx, cnt);
                        }
                    }
                }
                else
                {
                    if(*idx >= 0x1F && *idx <= 0x7e)
                    {
                        if(dummy_idx < dummy_end)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;
                        }
                        else
                        {
                            FatalError("%s(%d)=> ParsePattern() "
                                    "dummy buffer overflow!\n", file_name, file_line);
                        }

                        if(literal)
                        {
                            literal = 0;
                        }
                    }
                    else
                    {
                        if(literal)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;
                            DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Clearing literal\n"););
                            literal = 0;
                        }
                        else
                        {
                            FatalError("%s(%d)=> character value out "
                                    "of range, try a binary buffer\n", 
                                    file_name, file_line);
                        }
                    }
                }

                break;
        }

        dummy_idx++;
        idx++;
        cnt++;
    }
    /* ...END BAD JUJU */

    /* error prunning */

    if (literal) {
        FatalError("%s(%d)=> backslash escape is not "
           "completed\n", file_name, file_line);
    }
    if (hexmode) {
        FatalError("%s(%d)=> hexmode is not "
           "completed\n", file_name, file_line);
    }

    ds_idx = (PatternMatchData *) otn->ds_list[type];

    while(ds_idx->next != NULL)
        ds_idx = ds_idx->next;

    if((ds_idx->pattern_buf = (char *) calloc(dummy_size+1, sizeof(char))) 
       == NULL)
    {
        FatalError("ParsePattern() pattern_buf malloc failed!\n");
    }

    memcpy(ds_idx->pattern_buf, tmp_buf, dummy_size);

    ds_idx->pattern_size = dummy_size;
    ds_idx->search = uniSearch;
    
    make_precomp(ds_idx);
    ds_idx->exception_flag = exception_flag;

    ds_idx->pattern_max_jump_size = GetMaxJumpSize(ds_idx->pattern_buf, ds_idx->pattern_size);

    return;
}

static int CheckORPatternMatch(Packet * p, struct _OptTreeNode * otn_idx, 
                   OptFpList * fp_list)
{
    int found = 0;
    int dsize;
    char *dp;
    

    PatternMatchData *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "CheckPatternORMatch: "););
    
    idx = otn_idx->ds_list[PLUGIN_PATTERN_MATCH_OR];

    while(idx != NULL)
    {

        if((p->packet_flags & PKT_ALT_DECODE) && (idx->rawbytes == 0))
        {
            dsize = p->alt_dsize;
            dp = (char *) DecodeBuffer; /* decode.c */
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Using Alternative Decode buffer!\n"););
        }
        else
        {
            dsize = p->dsize;
            dp = (char *) p->data;
        }
        

        if(idx->offset > dsize)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                        "Initial offset larger than payload!\n"););

            goto sizetoosmall;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                        "testing pattern: %s\n", idx->pattern_buf););
            found = idx->search(dp, dsize, idx);

            if(!found)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                            "Pattern Match failed!\n"););
            }
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Checking the results\n"););

        if(found)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern Match "
                    "successful: %s!\n", idx->pattern_buf););

            return fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);

        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                        "Pattern match failed\n"););
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Stepping to next content keyword\n"););

    sizetoosmall:

        idx = idx->next;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                "No more keywords, exiting... \n"););

    return 0;
}

static int CheckANDPatternMatch(Packet *p, struct _OptTreeNode *otn_idx, 
                OptFpList *fp_list)
{
    int found = 0;
    int next_found;
    int dsize;
    char *dp;
    int origUseDoe;
    char *tmp_doe, *orig_doe, *start_doe;
    int ret;

    PatternMatchData *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "CheckPatternANDMatch: "););

    idx = fp_list->context;
    origUseDoe = idx->use_doe;

    if((p->packet_flags & PKT_ALT_DECODE) && (idx->rawbytes == 0))
    {
        dsize = p->alt_dsize;
        dp = (char *) DecodeBuffer; /* decode.c */
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Using Alternative Decode buffer!\n"););
    }
    else
    {
        dsize = p->dsize;
        dp = (char *) p->data;
    }

    /* this now takes care of all the special cases where we'd run
     * over the buffer */
    orig_doe = doe_ptr;
#ifndef NO_FOUND_ERROR
    found = idx->search(dp, dsize, idx);
    if ( found == -1 )
    {
        /* On error, mark as not found.  This is necessary to handle !content
           cases.  In that case, a search that is outside the given buffer will
           return 0, and !0 is 1, so a !content out of bounds will return true,
           which is not what we want.  */
        found = 0;
    }
    else
    {
        found = found ^ idx->exception_flag;
    }
#else
    /* Original code.  Does not account for searching outside the buffer. */
    found = (idx->search(dp, dsize, idx) ^ idx->exception_flag);
#endif

    if (InlineMode() && found && idx->replace_buf)
    {
        //fix the packet buffer to have the new string
        detect_depth = (char *)doe_ptr - idx->pattern_size - dp;

        ret = PayloadReplace(p, otn_idx, fp_list, detect_depth);
        if (ret == 0)
            return 0;
    }

    while (found)
    {
        /* save where we last did the pattern match */
        tmp_doe = doe_ptr;

        /* save start doe as beginning of this pattern + non-repeating length*/
        start_doe = doe_ptr - idx->pattern_size + idx->pattern_max_jump_size;

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern Match successful!\n"););      
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Check next functions!\n"););

        /* Try evaluating the rest of the rules chain */
        next_found= fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);

        if(next_found != 0) 
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Next functions matched!\n"););

            /* We found a successful match, return that this rule has fired off */
            return next_found;
        }
        else if(tmp_doe != NULL)
        {
            int new_dsize = dsize-(start_doe-dp);

            /* if the next option isn't relative and it failed, we're done */
            if (fp_list->next->isRelative == 0)
                return 0;

            if(new_dsize <= 0 || new_dsize > dsize)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                        "The new dsize is less than <= 0 or > "
                                        "the the original dsize;returning "
                                        "false\n"););
                idx->use_doe = origUseDoe;
                return 0;
            }

            if (orig_doe)
            {
                /* relative to a previously found pattern */
                if (((idx->distance != 0) && (start_doe - orig_doe > idx->distance)) ||
                    ((idx->offset != 0) && (start_doe - orig_doe > idx->offset)) )
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                            "The next starting point to search "
                                            "from is beyond the original "
                                            "distance;returning false\n"););
                    idx->use_doe = origUseDoe;
                    return 0;
                }

                if (((idx->within != 0) &&
                     (start_doe - orig_doe + idx->pattern_size > (unsigned int)idx->within)) ||
                    ((idx->depth != 0) &&
                     (start_doe - orig_doe + idx->pattern_size > (unsigned int)idx->depth)) )
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                            "The next starting point to search "
                                            "from is beyond the original "
                                            "within;returning false\n"););
                    idx->use_doe = origUseDoe;
                    return 0;
                }
            }
            else
            {
                /* relative to beginning of data */
                if (((idx->distance != 0) && (start_doe - dp > idx->distance)) ||
                    ((idx->offset != 0) && (start_doe - dp > idx->offset)) )
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                            "The next starting point to search "
                                            "from is beyond the original "
                                            "distance;returning false\n"););
                    idx->use_doe = origUseDoe;
                    return 0;
                }

                if (((idx->within != 0) &&
                     (start_doe - dp + idx->pattern_size > (unsigned int)idx->within)) ||
                    ((idx->depth != 0) &&
                     (start_doe - dp + idx->pattern_size > (unsigned int)idx->depth)) )
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                            "The next starting point to search "
                                            "from is beyond the original "
                                            "within;returning false\n"););
                    idx->use_doe = origUseDoe;
                    return 0;
                }
            }

            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "At least ONE of the next functions does to match!\n"););      
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Start search again from a next point!\n"););

            /* Start the search again from the last set of contents, with a new depth and dsize */
            doe_ptr = start_doe;
            idx->use_doe = 1;
            found = (idx->search(start_doe, new_dsize,idx) ^ idx->exception_flag);
            
            /*
            **  If we haven't updated doe since we set it at the beginning
            **  of the loop, then that means we have already done the exact 
            **  same search previously, and have nothing else to gain from
            **  doing the same search again.
            */
            if(start_doe == (char *)doe_ptr)
            {
                idx->use_doe = origUseDoe;
                return 0;
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                                    "Returning 0 because tmp_doe is NULL\n"););
            
            idx->use_doe = origUseDoe;
            return 0;
        }
        
    }
    
    idx->use_doe = origUseDoe;
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Pattern match failed\n"););
    return 0;
}

/************************************************************************/
/************************************************************************/
/************************************************************************/

static int CheckUriPatternMatch(Packet *p, struct _OptTreeNode *otn_idx, 
                OptFpList *fp_list)
{
    int found = 0;
    int i;
    PatternMatchData *idx;

    if(p->uri_count <= 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_HTTP_DECODE,
                    "CheckUriPatternMatch: p->uri_count is %d. Returning",
                    p->uri_count););
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "CheckUriPatternMatch: "););

    idx = fp_list->context;

    for(i=0;i < p->uri_count; i++)
    {

#ifdef DEBUG /* for variable declaration */
        int j;

        DebugMessage(DEBUG_HTTP_DECODE,"Checking against URL: ");
        for(j=0; j<=UriBufs[i].length; j++)
        {
            DebugMessage(DEBUG_HTTP_DECODE, "%c", UriBufs[i].uri[j]);
        }
        DebugMessage(DEBUG_HTTP_DECODE,"\n");

#endif /* DEBUG */
        DEBUG_WRAP(DebugMessage(DEBUG_HTTP_DECODE,"Checking for %s pattern in "
            "buffer %d: ",
            idx->uri_buffer == HTTP_BUFFER_CLIENT_BODY ?
                "http_client_body" : "http_uri", i););

        if (idx->uri_buffer != i)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_HTTP_DECODE,"Continuing past buffer "
                "for %s, looking for buffer %s\n",
                i == HTTP_BUFFER_CLIENT_BODY ? "http_client_body" : "http_uri",
                idx->uri_buffer == HTTP_BUFFER_CLIENT_BODY ?
                    "http_client_body" : "http_uri"););
            continue;
        }

        /* 
         * have to reset the doe_ptr for each new UriBuf 
         */
        doe_ptr = NULL;

        /* this now takes care of all the special cases where we'd run
         * over the buffer */
        found = (idx->search(UriBufs[i].uri, UriBufs[i].length, idx) ^ idx->exception_flag);
        
        if(found)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern Match successful!\n"););
            /* call the next function in the OTN */
            return fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);        
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Pattern match failed\n"););

    return 0;
}



/****************************************************************************
 *
 * Function: ParseContentListFile(char *, OptTreeNode *, int protocol)
 *
 * Purpose:  Read the content_list file a line at a time, put the content of
 *           the line into buffer
 *
 * Arguments:otn => rule including the list
 *           file => list file filename
 *           protocol => protocol
 *
 * Returns: void function
 *
 ***************************************************************************/
static void ParseContentListFile(char *file, OptTreeNode * otn, int protocol)
{
    FILE *thefp;                /* file pointer for the content_list file */
    char buf[STD_BUF+1];        /* file read buffer */
    char rule_buf[STD_BUF+1];   /* content keyword buffer */
    int frazes_count;           /* frazes counter */


#ifdef DEBUG
    PatternMatchData *idx;
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Opening content_list file: %s\n", file););
#endif /* DEBUG */
    /* open the list file */
    if((thefp = fopen(file, "r")) == NULL)
    {
        FatalError("Unable to open list file: %s\n", file);
    }
    /* clear the line and rule buffers */
    bzero((char *) buf, STD_BUF);
    bzero((char *) rule_buf, STD_BUF);
    frazes_count = 0;

    /* loop thru each list_file line and content to the rule */
    while((fgets(buf, STD_BUF-2, thefp)) != NULL)
    {
        /* inc the line counter */
        list_file_line++;

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Got line %d: %s", 
                list_file_line, buf););

        /* if it's not a comment or a <CR>, send it to the parser */
        if((buf[0] != '#') && (buf[0] != 0x0a) && (buf[0] != ';'))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Adding content keyword: %s", buf););

            frazes_count++;
            strip(buf);

            NewNode(otn, PLUGIN_PATTERN_MATCH_OR);

            /* check and add content keyword */
            ParsePattern(buf, otn, PLUGIN_PATTERN_MATCH_OR);

            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                        "Content keyword %s\" added!\n", buf););
        }
    }
#ifdef DEBUG
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "%d frazes read...\n", frazes_count););
    idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH_OR];
    
    if(idx == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "No patterns loaded\n"););
    }
    else
    {
        while(idx != NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern = %s\n", 
                    idx->pattern_buf););
            idx = idx->next;
        }
    }
#endif /* DEBUG */
    
    fclose(thefp);

    return;
}
