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
#ifndef __RULES_H__
#define __RULES_H__


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event.h"
#include "decode.h"
#include "signature.h"
#include "parser/IpAddrSet.h"
#include "spo_plugbase.h"

#ifdef SUNOS
    #define INADDR_NONE -1
#endif

#ifdef SOLARIS
    #define INADDR_NONE -1
#endif

#define RULE_LOG         0
#define RULE_PASS        1
#define RULE_ALERT       2
#define RULE_VAR         3
#define RULE_INCLUDE     4
#define RULE_PREPROCESS  5
#define RULE_OUTPUT      6
#define RULE_ACTIVATE    7
#define RULE_DYNAMIC     8
#define RULE_CONFIG      9
#define RULE_DECLARE     10
#define RULE_THRESHOLD   11
#define RULE_SUPPRESS    12
#define RULE_UNKNOWN     13
#define RULE_DROP        14
#define RULE_SDROP       15
#define RULE_REJECT      16
#define RULE_STATE       17
#ifdef DYNAMIC_PLUGIN
#define RULE_DYNAMICENGINE 18
#define RULE_DYNAMICDETECTION 19
#define RULE_DYNAMICPREPROCESSOR 20
#endif

#define EXCEPT_SRC_IP  0x01
#define EXCEPT_DST_IP  0x02
#define ANY_SRC_PORT   0x04
#define ANY_DST_PORT   0x08
#define ANY_FLAGS      0x10
#define EXCEPT_SRC_PORT 0x20
#define EXCEPT_DST_PORT 0x40
#define BIDIRECTIONAL   0x80
#define ANY_SRC_IP      0x100
#define ANY_DST_IP      0x200

#define EXCEPT_IP      0x01

#define R_FIN          0x01
#define R_SYN          0x02
#define R_RST          0x04
#define R_PSH          0x08
#define R_ACK          0x10
#define R_URG          0x20
#define R_RES2         0x40
#define R_RES1         0x80

#define MODE_EXIT_ON_MATCH   0
#define MODE_FULL_SEARCH     1

#define CHECK_SRC            0x01
#define CHECK_DST            0x02
#define INVERSE              0x04

#define SESSION_PRINTABLE    1
#define SESSION_ALL          2

#define RESP_RST_SND         0x01
#define RESP_RST_RCV         0x02
#define RESP_BAD_NET         0x04
#define RESP_BAD_HOST        0x08
#define RESP_BAD_PORT        0x10

#define MODE_EXIT_ON_MATCH   0
#define MODE_FULL_SEARCH     1

#define SRC                  0
#define DST                  1

#ifndef PARSERULE_SIZE
#define PARSERULE_SIZE	     65535
#endif

#ifndef UINT64
#define UINT64 unsigned long long
#endif

/*  D A T A  S T R U C T U R E S  *********************************************/
/* I'm forward declaring the rules structures so that the function
   pointer lists can reference them internally */

struct _OptTreeNode;      /* forward declaration of OTN data struct */
struct _RuleTreeNode;     /* forward declaration of RTN data struct */
struct _ListHead;    /* forward decleartion of ListHead data struct */

/* function pointer list for rule head nodes */
typedef struct _RuleFpList
{
    /* context data for this test */
    void *context;

    /* rule check function pointer */
    int (*RuleHeadFunc)(Packet *, struct _RuleTreeNode *, struct _RuleFpList *);

    /* pointer to the next rule function node */
    struct _RuleFpList *next;
} RuleFpList;

/* same as the rule header FP list */
typedef struct _OptFpList
{
    /* context data for this test */
    void *context;

    int (*OptTestFunc)(Packet *, struct _OptTreeNode *, struct _OptFpList *);

    struct _OptFpList *next;

    unsigned char isRelative;

} OptFpList;

typedef struct _RspFpList
{
    int (* ResponseFunc)(Packet *, struct _RspFpList *);
    void *params; /* params for the plugin.. type defined by plugin */
    struct _RspFpList *next;
} RspFpList;



typedef struct _TagData
{
    int tag_type;       /* tag type (session/host) */
    int tag_seconds;    /* number of "seconds" units to tag for */
    int tag_packets;    /* number of "packets" units to tag for */
    int tag_bytes;      /* number of "type" units to tag for */
    int tag_metric;     /* (packets | seconds | bytes) units */
    int tag_direction;  /* source or dest, used for host tagging */
} TagData;


typedef struct _OptTreeNode
{
    /* plugin/detection functions go here */
    OptFpList *opt_func;
    RspFpList *rsp_func;  /* response functions */
    OutputFuncNode *outputFuncs; /* per sid enabled output functions */

    /* the ds_list is absolutely essential for the plugin system to work,
       it allows the plugin authors to associate "dynamic" data structures
       with the rule system, letting them link anything they can come up 
       with to the rules list */
    void *ds_list[64];   /* list of plugin data struct pointers */

    int chain_node_number;

    int type;            /* what do we do when we match this rule */
    int evalIndex;       /* where this rule sits in the evaluation sets */
                            
    int proto;           /* protocol, added for integrity checks 
                            during rule parsing */
    struct _RuleTreeNode *proto_node; /* ptr to head part... */
    int session_flag;    /* record session data */

    char *logto;         /* log file in which to write packets which 
                            match this rule*/
    /* metadata about signature */
    SigInfo sigInfo;

    u_int8_t stateless;  /* this rule can fire regardless of session state */
    u_int8_t established; /* this rule can only fire if it is established */
    u_int8_t unestablished;

    Event event_data;

    TagData *tag;

    /* stuff for dynamic rules activation/deactivation */
    int active_flag;
    int activation_counter;
    int countdown;
    int activates;
    int activated_by;

    u_int8_t  threshold_type; /* type of threshold we're watching */
    u_int32_t threshold;    /* number of events between alerts */
    u_int32_t window;       /* number of seconds before threshold times out */

    struct _OptTreeNode *OTN_activation_ptr;
    struct _RuleTreeNode *RTN_activation_ptr;

    struct _OptTreeNode *next;
    struct _RuleTreeNode *rtn;

    struct _OptTreeNode *nextSoid;

    u_int8_t failedCheckBits;

    int rule_state; /* Enabled or Disabled */

#ifdef PERF_PROFILING
    UINT64 ticks;
    UINT64 ticks_match;
    UINT64 ticks_no_match;
    u_int32_t checks;
    u_int32_t matches;
    u_int32_t alerts;
    u_int8_t noalerts; 
#endif

} OptTreeNode;



typedef struct _ActivateList
{
    int activated_by;
    struct _ActivateList *next;
} ActivateList;


#if 0 /* RELOCATED to parser/IpAddrSet.h */
typedef struct _IpAddrSet
{
    u_int32_t ip_addr;   /* IP addr */
    u_int32_t netmask;   /* netmask */
    u_int8_t  addr_flags; /* flag for normal/exception processing */

    struct _IpAddrSet *next;
} IpAddrSet;
#endif /* RELOCATED to parser/IpAddrSet.h */

typedef struct _RuleTreeNode
{
    RuleFpList *rule_func; /* match functions.. (Bidirectional etc.. ) */

    int head_node_number;

    int type;

    IpAddrSet *sip;
    IpAddrSet *dip;

    int not_sp_flag;     /* not source port flag */

    u_short hsp;         /* hi src port */
    u_short lsp;         /* lo src port */

    int not_dp_flag;     /* not dest port flag */

    u_short hdp;         /* hi dest port */
    u_short ldp;         /* lo dest port */

    u_int32_t flags;     /* control flags */

    /* stuff for dynamic rules activation/deactivation */
    int active_flag;
    int activation_counter;
    int countdown;
    ActivateList *activate_list;

    struct _RuleTreeNode *right;  /* ptr to the next RTN in the list */

    OptTreeNode *down;   /* list of rule options to associate with this
                            rule node */
    struct _ListHead *listhead;

} RuleTreeNode;

struct _RuleListNode;

typedef struct _ListHead
{
    RuleTreeNode *IpList;
    RuleTreeNode *TcpList;
    RuleTreeNode *UdpList;
    RuleTreeNode *IcmpList;
    struct _OutputFuncNode *LogList;
    struct _OutputFuncNode *AlertList;
    struct _RuleListNode *ruleListNode;
} ListHead; 

typedef struct _RuleListNode
{
    ListHead *RuleList;         /* The rule list associated with this node */
    int mode;                   /* the rule mode */
    int rval;                   /* 0 == no detection, 1 == detection event */
    int evalIndex;              /* eval index for this rule set */
    char *name;                 /* name of this rule list (for debugging)  */
    struct _RuleListNode *next; /* the next RuleListNode */
} RuleListNode;

struct VarEntry
{
    char *name;
    char *value;
    unsigned char flags;
#define VAR_STATIC      1
    struct VarEntry *prev;
    struct VarEntry *next;
};

#endif /* __RULES_H__ */
