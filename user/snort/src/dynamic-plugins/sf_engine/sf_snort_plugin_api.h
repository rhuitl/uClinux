/*
 * sf_snort_plugin.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005-2006 Sourcefire Inc.
 *
 * Author: Steve Sturges
 *         Andy Mullican
 *
 * Date: 5/2005
 *
 * Sourcefire Black-box Plugin API for rules
 *
 */
#ifndef SF_SNORT_PLUGIN_API_H_
#define SF_SNORT_PLUGIN_API_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "pcre.h"
#include "stdio.h"

#ifndef WIN32
#include <netinet/in.h>
#include <sys/types.h>
#else
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned long u_int32_t;
typedef char int8_t;
typedef short int16_t;
typedef long int32_t;
#include <winsock2.h>
#include <windows.h>
#endif

#define ANY_NET         "any"
#define HOME_NET        "$HOME_NET"
#define EXTERNAL_NET    "$EXTERNAL_NET"
#define ANY_PORT        "any"
#define HTTP_SERVERS    "$HTTP_SERVERS"
#define HTTP_PORTS      "$HTTP_PORTS"
#define SMTP_SERVERS    "$SMTP_SERVERS"

#ifdef WIN32
#ifdef SF_SNORT_ENGINE_DLL
#define ENGINE_LINKAGE __declspec(dllexport)
#else
#define ENGINE_LINKAGE __declspec(dllimport)
#endif
#else /* WIN32 */
#define ENGINE_LINKAGE
#endif /* WIN32 */

#define RULE_MATCH 1
#define RULE_NOMATCH 0

#define RULE_DIRECTIONAL 0
#define RULE_BIDIRECTIONAL 1

#define CONTENT_MATCH          1
#define CONTENT_NOMATCH        0
#define CONTENT_TYPE_MISMATCH -1
#define CONTENT_TYPE_MISSING  -2
#define CONTENT_CURSOR_ERROR  -3
#define CURSOR_IN_BOUNDS       1
#define CURSOR_OUT_OF_BOUNDS   0

#define CONTENT_NOCASE          0x01
#define CONTENT_RELATIVE        0x02
#define CONTENT_UNICODE2BYTE    0x04
#define CONTENT_UNICODE4BYTE    0x08
#define CONTENT_FAST_PATTERN    0x10
#define CONTENT_END_BUFFER      0x20

#define CONTENT_BUF_NORMALIZED  0x100
#define CONTENT_BUF_RAW         0x200
#define CONTENT_BUF_URI         0x400
#define CONTENT_BUF_POST        0x800

#define BYTE_LITTLE_ENDIAN      0x0000
#define BYTE_BIG_ENDIAN         0x1000

#define EXTRACT_AS_BYTE         0x010000
#define EXTRACT_AS_STRING       0x020000
#define EXTRACT_AS_DEC          0x100000
#define EXTRACT_AS_OCT          0x200000
#define EXTRACT_AS_HEX          0x400000
#define EXTRACT_AS_BIN          0x800000

#define JUMP_FROM_BEGINNING     0x01000000
#define JUMP_ALIGN              0x02000000

#define NOT_FLAG                0x10000000

#define CHECK_EQ            0
#define CHECK_NEQ           1
#define CHECK_LT            2
#define CHECK_GT            3
#define CHECK_LTE           4
#define CHECK_GTE           5
#define CHECK_AND           6
#define CHECK_XOR           7
#define CHECK_ALL           8
#define CHECK_ATLEASTONE    9
#define CHECK_NONE          10

typedef struct _ContentInfo
{
    u_int8_t *pattern;
    u_int32_t depth;
    int32_t   offset;
    u_int32_t flags;        /* must include a CONTENT_BUF_X */
    void     *boyer_ptr;
    u_int8_t *patternByteForm;
    u_int32_t patternByteFormLength;
    u_int32_t incrementLength;
} ContentInfo;

typedef struct _CursorInfo
{
    int32_t   offset;
    u_int32_t flags;        /* specify one of CONTENT_BUF_X */
} CursorInfo;

/*
pcre.h provides flags:

PCRE_CASELESS
PCRE_MULTILINE
PCRE_DOTALL
PCRE_EXTENDED
PCRE_ANCHORED
PCRE_DOLLAR_ENDONLY
PCRE_UNGREEDY
*/

typedef struct _PCREInfo
{
    char     *expr;
    void     *compiled_expr;
    void     *compiled_extra;
    u_int32_t compile_flags;
    u_int32_t flags; /* must include a CONTENT_BUF_X */
} PCREInfo;

#define FLOWBIT_SET       0x01  
#define FLOWBIT_UNSET     0x02
#define FLOWBIT_TOGGLE    0x04
#define FLOWBIT_ISSET     0x08
#define FLOWBIT_ISNOTSET  0x10
#define FLOWBIT_RESET     0x20
#define FLOWBIT_NOALERT   0x40

typedef struct _FlowBitsInfo
{
    char      *flowBitsName;
    u_int8_t   operation;
    u_int32_t  id;
    u_int32_t  flags;
} FlowBitsInfo;

typedef struct _ByteData
{
    u_int32_t bytes;      /* Number of bytes to extract */
    u_int32_t op;         /* Type of byte comparison, for checkValue */
    u_int32_t value;      /* Value to compare value against, for checkValue, or extracted value */
    int32_t   offset;     /* Offset from cursor */
    u_int32_t multiplier; /* Used for byte jump -- 32bits is MORE than enough */
    u_int32_t flags;      /* must include a CONTENT_BUF_X */
} ByteData;

typedef struct _ByteExtract
{
    u_int32_t bytes;      /* Number of bytes to extract */
    int32_t   offset;     /* Offset from cursor */
    u_int32_t multiplier; /* Multiply value by this (similar to byte jump) */
    u_int32_t flags;      /* must include a CONTENT_BUF_X */
    char *refId;          /* To match up with a DynamicElement refId */
    void *memoryLocation; /* Location to store the data extracted */
} ByteExtract;

#define FLOW_ESTABLISHED 0x10
#define FLOW_IGNORE_REASSEMBLED 0x1000
#define FLOW_ONLY_REASSMBLED    0x2000
#define FLOW_FR_SERVER   0x40
#define FLOW_TO_CLIENT   0x40 /* Just for redundancy */
#define FLOW_TO_SERVER   0x80
#define FLOW_FR_CLIENT   0x80 /* Just for redundancy */

typedef struct _FlowFlags
{
    u_int32_t   flags;
} FlowFlags;


#define ASN1_ABS_OFFSET 1
#define ASN1_REL_OFFSET 2

typedef struct _Asn1Context
{
    int bs_overflow;
    int double_overflow;
    int print;
    int length;
    unsigned int max_length;
    int offset;
    int offset_type;
    u_int32_t  flags;
} Asn1Context;

#define IP_HDR_ID           0x0001  /* IP Header ID */
#define IP_HDR_PROTO        0x0002  /* IP Protocol */
#define IP_HDR_FRAGBITS     0x0003  /* Frag Flags set in IP Header */
#define IP_HDR_FRAGOFFSET   0x0004  /* Frag Offset set in IP Header */
#define IP_HDR_OPTIONS      0x0005  /* IP Options -- is option xx included */
#define IP_HDR_TTL          0x0006  /* IP Time to live */
#define IP_HDR_TOS          0x0007  /* IP Type of Service */
#define IP_HDR_OPTCHECK_MASK 0x000f

#define TCP_HDR_ACK         0x0010  /* TCP Ack Value */
#define TCP_HDR_SEQ         0x0020  /* TCP Seq Value */
#define TCP_HDR_FLAGS       0x0030  /* Flags set in TCP Header */
#define TCP_HDR_OPTIONS     0x0040  /* TCP Options -- is option xx included */
#define TCP_HDR_WIN         0x0050  /* TCP Window */
#define TCP_HDR_OPTCHECK_MASK 0x00f0

#define ICMP_HDR_CODE       0x1000  /* ICMP Header Code */
#define ICMP_HDR_TYPE       0x2000  /* ICMP Header Type */
#define ICMP_HDR_ID         0x3000  /* ICMP ID for ICMP_ECHO/ICMP_ECHO_REPLY */
#define ICMP_HDR_SEQ        0x4000  /* ICMP ID for ICMP_ECHO/ICMP_ECHO_REPLY */
#define ICMP_HDR_OPTCHECK_MASK 0xf000

typedef struct _HdrOptCheck
{
    u_int16_t hdrField;   /* Field to check */
    u_int32_t op;         /* Type of comparison */
    u_int32_t value;      /* Value to compare value against */
    u_int32_t mask_value; /* bits of value to ignore */
    u_int32_t flags;
} HdrOptCheck;

#define DYNAMIC_TYPE_INT_STATIC 1
#define DYNAMIC_TYPE_INT_REF    2

typedef struct _DynamicElement
{
    char dynamicType;           /* type of this field - static or reference */
    char *refId;                /* reference ID (NULL if static) */
    union
    {
        void *voidPtr;          /* Holder */
        int32_t staticInt;        /* Value of static */
        int32_t *dynamicInt;  /* Pointer to value of dynamic */
    } data;
} DynamicElement;

typedef struct _LoopInfo
{
    DynamicElement *start;      /* Starting value of FOR loop (i=start) */
    DynamicElement *end;        /* Ending value of FOR loop (i OP end) */
    DynamicElement *increment;  /* Increment value of FOR loop (i+= increment) */
    u_int32_t op;               /* Type of comparison for loop termination */
    CursorInfo *cursorAdjust;   /* How to move cursor each iteration of loop */
    struct _Rule *subRule;      /* Pointer to SubRule & options to evaluate within
                                 * the loop */
    u_int8_t initialized;       /* Loop initialized properly (safeguard) */
    u_int32_t flags;            /* can be used to negate loop results, specifies
                                 * relative. */
} LoopInfo;

typedef struct _PreprocessorOption
{
    char *optionName;
    char *optionParameters;
    u_int32_t flags;
    void *optionInit;
    void *optionEval;
    //PreprocOptionInit optionInit;
    //PreprocOptionEval optionEval;
    void *dataPtr;
} PreprocessorOption;

#define OPTION_TYPE_PREPROCESSOR 0x00
#define OPTION_TYPE_CONTENT      0x01
#define OPTION_TYPE_PCRE         0x02
#define OPTION_TYPE_FLOWBIT      0x03
#define OPTION_TYPE_FLOWFLAGS    0x04
#define OPTION_TYPE_ASN1         0x05
#define OPTION_TYPE_CURSOR       0x06
#define OPTION_TYPE_HDR_CHECK    0x07
#define OPTION_TYPE_BYTE_TEST    0x08
#define OPTION_TYPE_BYTE_JUMP    0x09
#define OPTION_TYPE_BYTE_EXTRACT 0x10
#define OPTION_TYPE_SET_CURSOR   0x11
#define OPTION_TYPE_LOOP         0x12

typedef struct _RuleOption
{
    int optionType;
    union
    {
        void *ptr;
        ContentInfo *content;
        CursorInfo *cursor;
        PCREInfo *pcre;
        FlowBitsInfo *flowBit;
        ByteData *byte;
        ByteExtract *byteExtract;
        FlowFlags *flowFlags;
        Asn1Context *asn1;
        HdrOptCheck *hdrData;
        LoopInfo    *loop;
        PreprocessorOption *preprocOpt;
    } option_u;
} RuleOption;

typedef struct _IPInfo
{
    u_int8_t protocol;
    char *   src_addr;
    char *   src_port; /* 0 for non TCP/UDP */
    char     direction;     /* non-zero is bi-directional */
    char *   dst_addr;
    char *   dst_port; /* 0 for non TCP/UDP */
} IPInfo;

typedef struct _RuleReference
{
    char *systemName;
    char *refIdentifier;
} RuleReference;

#define REGISTER_RULE 1
#define DONT_REGISTER_RULE 0

typedef struct _RuleInformation
{
    u_int32_t genID;
    u_int32_t sigID;
    u_int32_t revision;
    char     *classification; /* String format of classification name */
    u_int32_t priority;
    char     *message;
    RuleReference **references; /* NULL terminated array of references */
} RuleInformation;

typedef int (*ruleEvalFunc)(void *);

typedef struct _Rule
{
    IPInfo ip;
    RuleInformation info;
    
    RuleOption **options; /* NULL terminated array of RuleOption union */

    ruleEvalFunc evalFunc;

    char initialized;     /* Rule Initialized, used internally */
    u_int32_t numOptions; /* Rule option count, used internally */
    char noAlert;         /* Flag with no alert, used internally */
    void *ruleData;    /* Hash table for dynamic data pointers */

} Rule;


ENGINE_LINKAGE int RegisterRules(Rule **rules);
ENGINE_LINKAGE int DumpRules(char *rulesFileName, Rule **rules);

ENGINE_LINKAGE int contentMatch(void *p, ContentInfo* content, u_int8_t **cursor);
ENGINE_LINKAGE int checkFlow(void *p, FlowFlags *flowFlags);
ENGINE_LINKAGE int extractValue(void *p, ByteExtract *byteExtract, u_int8_t *cursor);
ENGINE_LINKAGE int processFlowbits(void *p, FlowBitsInfo *flowBits);
ENGINE_LINKAGE int setCursor(void *p, CursorInfo *cursorInfo, u_int8_t **cursor);
ENGINE_LINKAGE int checkCursor(void *p, CursorInfo *cursorInfo, u_int8_t *cursor);
ENGINE_LINKAGE int checkValue(void *p, ByteData *byteData, u_int32_t value, u_int8_t *cursor);
/* Same as extractValue plus checkValue */
ENGINE_LINKAGE int byteTest(void *p, ByteData *byteData, u_int8_t *cursor);
/* Same as extractValue plus setCursor */
ENGINE_LINKAGE int byteJump(void *p, ByteData *byteData, u_int8_t **cursor);
ENGINE_LINKAGE int pcreMatch(void *p, PCREInfo* pcre, u_int8_t **cursor);
ENGINE_LINKAGE int detectAsn1(void *p, Asn1Context* asn1, u_int8_t *cursor);
ENGINE_LINKAGE int checkHdrOpt(void *p, HdrOptCheck *optData);
ENGINE_LINKAGE int loopEval(void *p, LoopInfo *loop, u_int8_t **cursor);
ENGINE_LINKAGE int preprocOptionEval(void *p, PreprocessorOption *preprocOpt, u_int8_t **cursor);
ENGINE_LINKAGE void setTempCursor(u_int8_t **temp_cursor, u_int8_t **cursor);
ENGINE_LINKAGE void revertTempCursor(u_int8_t **temp_cursor, u_int8_t **cursor);
ENGINE_LINKAGE int ruleMatch(void *p, Rule *rule);
ENGINE_LINKAGE int MatchDecryptedRC4(u_int8_t *key, u_int16_t keylen, u_int8_t *encrypted_data, 
                                                u_int8_t *plain_data, u_int16_t datalen);


#endif /* SF_SNORT_PLUGIN_API_H_ */

