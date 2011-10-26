/* $Id$ */
/*
 ** Copyright (C) 2002-2006 Sourcefire, Inc.
 ** Author: Martin Roesch
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

/* sp_byte_jump 
 * 
 * Purpose:
 *      Grab some number of bytes, convert them to their numeric 
 *      representation, jump the doe_ptr up that many bytes (for
 *      further pattern matching/byte_testing).
 *
 *
 * Arguments:
 *      Required:
 *      <bytes_to_grab>: number of bytes to pick up from the packet
 *      <offset>: number of bytes into the payload to grab the bytes
 *      Optional:
 *      ["relative"]: offset relative to last pattern match
 *      ["big"]: process data as big endian (default)
 *      ["little"]: process data as little endian
 *      ["string"]: converted bytes represented as a string needing conversion
 *      ["hex"]: converted string data is represented in hexidecimal
 *      ["dec"]: converted string data is represented in decimal
 *      ["oct"]: converted string data is represented in octal
 *      ["align"]: round the number of converted bytes up to the next 
 *                 32-bit boundry
 *   
 *   sample rules:
 *   alert udp any any -> any 32770:34000 (content: "|00 01 86 B8|"; \
 *       content: "|00 00 00 01|"; distance: 4; within: 4; \
 *       byte_jump: 4, 12, relative, align; \
 *       byte_test: 4, >, 900, 20, relative; \
 *       msg: "statd format string buffer overflow";)
 *
 * Effect:
 *
 *      Reads in the indicated bytes, converts them to an numeric 
 *      representation and then jumps the doe_ptr up
 *      that number of bytes.  Returns 1 if the jump is in range (within the
 *      packet) and 0 if it's not.
 *
 * Comments:
 *
 * Any comments?
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>

#include "bounds.h"
#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "mstring.h"
#include "byte_extract.h"

extern u_int8_t *doe_ptr;
extern u_int8_t DecodeBuffer[DECODE_BLEN];

typedef struct _ByteJumpData
{
    u_int32_t bytes_to_grab; /* number of bytes to compare */
    int32_t offset;
    u_int8_t relative_flag;
    u_int8_t data_string_convert_flag;
    u_int8_t from_beginning_flag;
    u_int8_t align_flag;
    u_int8_t endianess;
    u_int32_t base;
    u_int32_t multiplier;

} ByteJumpData;

void ByteJumpInit(char *, OptTreeNode *, int);
void ByteJumpParse(char *, ByteJumpData *, OptTreeNode *);
int ByteJump(Packet *, struct _OptTreeNode *, OptFpList *);

/****************************************************************************
 * 
 * Function: SetupByteJump()
 *
 * Purpose: Load 'er up
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupByteJump(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("byte_jump", ByteJumpInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: ByteJump Setup\n"););
}


/****************************************************************************
 * 
 * Function: ByteJumpInit(char *, OptTreeNode *)
 *
 * Purpose: Generic rule configuration function.  Handles parsing the rule 
 *          information and attaching the associated detection function to
 *          the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *            protocol => protocol the rule is on (we don't care in this case)
 *
 * Returns: void function
 *
 ****************************************************************************/
void ByteJumpInit(char *data, OptTreeNode *otn, int protocol)
{
    ByteJumpData *idx;
    OptFpList *fpl;

    /* allocate the data structure and attach it to the
       rule's data struct list */
    idx = (ByteJumpData *) calloc(sizeof(ByteJumpData), sizeof(char));

    if(idx == NULL)
    {
        FatalError("%s(%d): Unable to allocate byte_jump data node\n", 
                   file_name, file_line);
    }

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ByteJumpParse(data, idx, otn);

    fpl = AddOptFuncToList(ByteJump, otn);

    /* attach it to the context node so that we can call each instance
     * individually
     */
    fpl->context = (void *) idx;

    if (idx->relative_flag == 1)
        fpl->isRelative = 1;

}



/****************************************************************************
 * 
 * Function: ByteJumpParse(char *, ByteJumpData *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            idx => pointer to the processed argument storage
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ByteJumpParse(char *data, ByteJumpData *idx, OptTreeNode *otn)
{
    char **toks;
    char *endp;
    int num_toks;
    char *cptr;
    int i =0;

    idx->multiplier = 1;

    toks = mSplit(data, ",", 12, &num_toks, 0);

    if(num_toks < 2)
        FatalError("ERROR %s (%d): Bad arguments to byte_jump: %s\n", file_name,
                file_line, data);

    /* set how many bytes to process from the packet */
    idx->bytes_to_grab = strtoul(toks[0], &endp, 10);

    if(endp==toks[0])
    {
        FatalError("%s(%d): Unable to parse as byte value %s\n",
                   file_name, file_line, toks[0]);
    }

    if(idx->bytes_to_grab > PARSELEN || idx->bytes_to_grab == 0)
    {
        FatalError("%s(%d): byte_jump can't process more than "
                "%d bytes!\n", file_name, file_line, PARSELEN);
    }

    /* set offset */
    idx->offset = strtol(toks[1], &endp, 10);

    if(endp==toks[1])
    {
        FatalError("%s(%d): Unable to parse as offset %s\n",
                   file_name, file_line, toks[1]);
    }

    i = 2;

    /* is it a relative offset? */
    if(num_toks > 2)
    {
        while(i < num_toks)
        {
            cptr = toks[i];

            while(isspace((int)*cptr)) {cptr++;}

            if(!strcasecmp(cptr, "relative"))
            {
                /* the offset is relative to the last pattern match */
                idx->relative_flag = 1;
            }
            else if(!strcasecmp(cptr, "from_beginning"))
            {
                idx->from_beginning_flag = 1;
            }
            else if(!strcasecmp(cptr, "string"))
            {
                /* the data will be represented as a string that needs 
                 * to be converted to an int, binary is assumed otherwise
                 */
                idx->data_string_convert_flag = 1;
            }
            else if(!strcasecmp(cptr, "little"))
            {
                idx->endianess = LITTLE;
            }
            else if(!strcasecmp(cptr, "big"))
            {
                /* this is the default */
                idx->endianess = BIG;
            }
            else if(!strcasecmp(cptr, "hex"))
            {
                idx->base = 16;
            }
            else if(!strcasecmp(cptr, "dec"))
            {
                idx->base = 10;
            }
            else if(!strcasecmp(cptr, "oct"))
            {
                idx->base = 8;
            }
            else if(!strcasecmp(cptr, "align"))
            {
                idx->align_flag = 1;
            }
            else if(!strncasecmp(cptr, "multiplier ", 11))
            {
                /* Format of this option is multiplier xx.
                 * xx is a positive base 10 number.
                 */
                char *mval = &cptr[11];
                long factor = 0;
                int multiplier_len = strlen(cptr);
                if (multiplier_len > 11)
                {
                    factor = strtol(mval, &endp, 10);
                }
                if ((factor <= 0) || (endp != cptr + multiplier_len))
                {
                    FatalError("%s(%d): invalid length multiplier \"%s\"\n", 
                            file_name, file_line, cptr);
                }
                idx->multiplier = factor;
            }
            else
            {
                FatalError("%s(%d): unknown modifier \"%s\"\n", 
                        file_name, file_line, cptr);
            }

            i++;
        }
    }

    /* idx->base is only set if the parameter is specified */
    if(!idx->data_string_convert_flag && idx->base)
    {
        FatalError("%s(%d): hex, dec and oct modifiers must be used in conjunction \n"
                   "        with the 'string' modifier\n", file_name, file_line);
    }

    mSplitFree(&toks, num_toks);
}


/****************************************************************************
 * 
 * Function: ByteJump(char *, OptTreeNode *, OptFpList *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: p => pointer to the decoded packet
 *            otn => pointer to the current rule's OTN
 *            fp_list => pointer to the function pointer list
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list 
 *
 ****************************************************************************/
int ByteJump(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    ByteJumpData *bjd;
    u_int32_t value = 0;
    u_int32_t jump_value = 0;
    int dsize;
    int use_alt_buffer = p->packet_flags & PKT_ALT_DECODE;
    char *base_ptr, *end_ptr, *start_ptr;

    bjd = (ByteJumpData *) fp_list->context;

    if(use_alt_buffer)
    {
        dsize = p->alt_dsize;
        start_ptr = (char *) DecodeBuffer;        
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "Using Alternative Decode buffer!\n"););

    }
    else
    {
        start_ptr = p->data;
        dsize = p->dsize;
    }

    DEBUG_WRAP(
            DebugMessage(DEBUG_PATTERN_MATCH,"[*] byte jump firing...\n");
            DebugMessage(DEBUG_PATTERN_MATCH,"payload starts at %p\n", start_ptr);
            );  /* END DEBUG_WRAP */

    /* save off whatever our ending pointer is */
    end_ptr = start_ptr + dsize;
    base_ptr = start_ptr;

    if(doe_ptr)
    {
        /* @todo: possibly degrade to use the other buffer, seems non-intuitive*/        
        if(!inBounds(start_ptr, end_ptr, doe_ptr))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "[*] byte jump bounds check failed..\n"););
            return 0;
        }
    }

    if(bjd->relative_flag && doe_ptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Checking relative offset!\n"););
        base_ptr = doe_ptr + bjd->offset;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "checking absolute offset %d\n", bjd->offset););
        base_ptr = start_ptr + bjd->offset;
    }

    /* Both of the extraction functions contain checks to insure the data
     * is always inbounds */
    
    if(!bjd->data_string_convert_flag)
    {
        if(byte_extract(bjd->endianess, bjd->bytes_to_grab,
                        base_ptr, start_ptr, end_ptr, &value))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "Byte Extraction Failed\n"););

            return 0;
        }
    }
    else
    {
        if(string_extract(bjd->bytes_to_grab, bjd->base,
                          base_ptr, start_ptr, end_ptr, &value))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "Byte Extraction Failed\n"););

            return 0;
        }

    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "grabbed %d bytes, value = %08X\n", 
                bjd->bytes_to_grab, value););

    /* Adjust the jump_value (# bytes to jump forward) with
     * the multiplier.
     */
    jump_value = value * bjd->multiplier;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "grabbed %d bytes, after multiplier value = %08X\n", 
                bjd->bytes_to_grab, jump_value););


    /* if we need to align on 32-bit boundries, round up to the next
     * 32-bit value
     */
    if(bjd->align_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, 
                    "offset currently at %d\n", jump_value););
        if ((jump_value % 4) != 0)
        {
            jump_value += (4 - (jump_value % 4));
        }
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "offset aligned to %d\n", jump_value););
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "Grabbed %d bytes at offset %d, value = 0x%08X\n",
                bjd->bytes_to_grab, bjd->offset, jump_value););

    if(bjd->from_beginning_flag)
    {
        /* Reset base_ptr if from_beginning */
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "jumping from beginning %d bytes\n", jump_value););
        base_ptr = start_ptr;

        /* from base, push doe_ptr ahead "value" number of bytes */
        doe_ptr = base_ptr + jump_value;
    }
    else
    {
        doe_ptr = base_ptr + bjd->bytes_to_grab + jump_value;
    }
   
    if(!inBounds(start_ptr, end_ptr, doe_ptr))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "tmp ptr is not in bounds %p\n", doe_ptr););
        return 0;
    }
    else
    {        
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* Never reached */
    return 0;
}
