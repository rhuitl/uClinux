/*
**  $Id$
**
**  fpdetect.c
**
**  Copyright (C) 2002-2005 Sourcefire,Inc
**  Author(s):  Dan Roelker <droelker@sourcefire.com>
**              Marc Norton <mnorton@sourcefire.com>
**              Andrew R. Baker <andrewb@snort.org>
**              Andrew J. Mullican <amullican@sourcefire.com>
**              Steven Sturges <ssturges@sourcefire.com>
**  NOTES
**  5.15.02 - Initial Source Code. Norton/Roelker
**  2002-12-06 - Modify event selection logic to fix broken custom rule types
**               arbitrary rule type ordering (ARB)
**  2005-02-08 - Track alerts per session so that they aren't double reported
**               for rebuilt packets.  AJM.
**  2005-02-17 - Track alerts per IP frag tracker so that they aren't double
**               reported for rebuilt frags.  SAS (code similar to AJM's for
**               per session tracking).
**
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#include "snort.h"
#include "detect.h"
#include "debug.h"
#include "util.h"
#include "tag.h"
#include "rules.h"
#include "pcrm.h"
#include "fpcreate.h"
#include "fpdetect.h"
#include "mpse.h"
#include "bitop.h"
#include "perf-event.h"
#include "sfthreshold.h"
#include "event_queue.h"
#include "inline.h"

#include "sp_pattern_match.h"
#include "spp_frag3.h"
#include "stream_api.h"

/*
**  This define is for the number of unique events
**  to match before choosing which event to log.
**  (Since we can only log one.) This define is the limit.
*/
#define MAX_EVENT_MATCH 100 

/*
**  This define enables set-wise signature detection for
**  IP and ICMP packets.  During early testing, the old
**  method of detection seemed faster for ICMP and IP 
**  signatures, but with modifications to the set-wise engine
**  performance became much better.  This define could be
**  taken out, but is still in for regression testing.
*/
#define FPSW

/*
**  GLOBALS
**  These variables are local to this file and deal with
**  configuration issues that are set in snort.conf through
**  variables.
*/

/*
**  This structure holds the configuration options for the
**  detection engine.  It is set by the functioncall:
**  fpSetDetectionOptions() which passes a pointer.
*/
static FPDETECT *fpDetect;

/*
**  Assorted global variables from the old detection engine
**  for backwards compatibility.
*/
extern PV          pv;  /* program vars (command line args) */
extern int         active_dynamic_nodes;
extern u_int16_t   event_id;
extern char        check_tags_flag;
extern OptTreeNode *otn_tmp;
extern u_int8_t    DecodeBuffer[DECODE_BLEN];
extern OptTreeNode *current_otn;
extern SNORT_EVENT_QUEUE g_event_queue;
/*              
**  MATCH_INFO
**  The events that are matched get held in this structure,
**  and iMatchIndex gets set to the event that holds the
**  highest priority.
*/
typedef struct {

 OTNX *MatchArray[MAX_EVENT_MATCH];
 int  iMatchCount;
 int  iMatchIndex;
 int  iMatchMaxLen;
 
}MATCH_INFO;

/*
**  OTNX_MATCH_DATA
**  This structure holds information that is
**  referenced during setwise pattern matches.
**  It also contains information regarding the
**  number of matches that have occurred and
**  the event to log based on the event comparison
**  function.
*/
typedef struct 
{
    PORT_GROUP * pg;
    Packet * p;
    int check_ports;

    MATCH_INFO *matchInfo;
    int iMatchInfoArraySize;
} OTNX_MATCH_DATA;

/*
**  Static function prototypes
*/
static INLINE int fpEvalOTN(OptTreeNode *List, Packet *p);
static INLINE int fpEvalRTN(RuleTreeNode *rtn,Packet *p, int check_ports);
static INLINE int fpEvalHeader(PORT_GROUP *port_group, Packet *p, 
        int check_ports);
static INLINE int fpEvalRTNSW(RuleTreeNode *rtn, OptTreeNode *otn, Packet *p, 
        int check_ports);
static INLINE int fpEvalHeaderIp(Packet *p, int ip_proto);
static INLINE int fpEvalHeaderIcmp(Packet *p);
static INLINE int fpEvalHeaderTcp(Packet *p);
static INLINE int fpEvalHeaderUdp(Packet *p);
static INLINE int fpEvalHeaderSW(PORT_GROUP *port_group, Packet *p, 
        int check_ports);
static int otnx_match (void* id, int index, void * data );               
static INLINE int fpAddMatch( OTNX_MATCH_DATA *omd, OTNX *otnx, int pLen );
static INLINE int fpAddSessionAlert(Packet *p, OTNX *otnx);
static INLINE int fpSessionAlerted(Packet *p, OTNX *otnx);
        
//static INLINE int fpLogEvent(RuleTreeNode *rtn, OptTreeNode *otn, Packet *p);

extern u_int8_t *doe_ptr;

static OTNX_MATCH_DATA omd;

#ifdef PERF_PROFILING
PreprocStats rulePerfStats;
#endif

/* initialize the global OTNX_MATCH_DATA variable */
int OtnXMatchDataInitialize()
{
    omd.iMatchInfoArraySize = pv.num_rule_types;
    if(!(omd.matchInfo = calloc(omd.iMatchInfoArraySize, 
                    sizeof(MATCH_INFO))))
    {
        FatalError("Out of memory initializing detection engine\n");
    }

    return 0;
}
    
/*
**  NAME
**    fpSetDetectionOptions::
**
**  DESCRIPTION
**    This function passes a pointer for us to set.  This pointer
**    contains the detection configuration options.  We use these for 
**    various optimizations.
**
**  FORMAL INPUTS
**    FPDETECT * - the address of the configuration structure to pass
**
**  FORMAL OUTPUTS
**    int - 0 is successful, failure code if otherwise.
**
*/
int fpSetDetectionOptions(FPDETECT *detect_options)
{
    fpDetect = detect_options;
    return 0;
}

/*
**
**  NAME
**    fpLogEvent::
**
**  DESCRIPTION
**    This function takes the corresponding RTN and OTN for a snort rule
**    and logs the event and packet that was alerted upon.  This 
**    function was pulled out of fpEvalSomething, so now we can log an
**    event no matter where we are.
**
**  FORMAL INPUTS
**    RuleTreeNode * - rtn for snort rule
**    OptTreeNode  * - otn for snort rule
**    Packet       * - packet that iliicited event.
*/
int fpLogEvent(RuleTreeNode *rtn, OptTreeNode *otn, Packet *p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                "   => Got rule match, rtn type = %d\n",
                rtn->type););

    if (otn->stateless)
    {
        /* Stateless rule, set the stateless bit */
        p->packet_flags |= PKT_STATELESS;
    }
    else
    {
        /* Not stateless, clear the stateless bit if it was set
         * from a previous rule.
         */
        p->packet_flags &= ~PKT_STATELESS;
    }

    if(p->packet_flags & PKT_STREAM_UNEST_UNI &&
            pv.assurance_mode == ASSURE_EST &&
            (!(p->packet_flags & PKT_REBUILT_STREAM)) &&
            otn->stateless == 0)
    {
        /*
        **  If InlineMode is on, then we still want to drop packets
        **  that are drop rules.  We just don't want to see the alert.
        */
        if(InlineMode())
        {
            if(rtn->type == RULE_DROP || rtn->type == RULE_SDROP)
                InlineDrop(p);
        }
        return 1;
    }
        
    /*
     *  Perform Thresholding Tests - also done in
     * detect.c/CallLogFuncs & CallAlertFuncs
     */
    if(p->iph)
    {
        if( !sfthreshold_test( otn->event_data.sig_generator,
                               otn->event_data.sig_id,
                               p->iph->ip_src.s_addr,
                               p->iph->ip_dst.s_addr,
                               p->pkth->ts.tv_sec) )
        {
            /*
            **  If InlineMode is on, then we still want to drop packets
            **  that are drop rules.  We just don't want to see the alert.
            */
            if(InlineMode())
            {
                if(rtn->type == RULE_DROP || rtn->type == RULE_SDROP)
                    InlineDrop(p);
            }
            
            return 1; /* Don't log it ! */
        }
    }
    else
    {
        if( !sfthreshold_test( otn->event_data.sig_generator,
                               otn->event_data.sig_id,
                               0,
                               0,
                               p->pkth->ts.tv_sec ) )
        {
            /*
            **  If InlineMode is on, then we still want to drop packets
            **  that are drop rules.  We just don't want to see the alert.
            */
            if(InlineMode())
            {
                if(rtn->type == RULE_DROP || rtn->type == RULE_SDROP)
                    InlineDrop(p);
            }

            return 1; /* Don't log it ! */
        }
    }

    /*
    **  Set the ref_time to 0 so we make the logging work right.
    */
    otn->event_data.ref_time.tv_sec = 0;
    
    /*
    **  Set otn_tmp because log.c uses it to log details
    **  of the event.  Maybe we should look into making this
    **  part of the log routines and not a global variable.
    **  This way we could support multiple events per packet.
    */
    otn_tmp = otn;
    OTN_PROFILE_ALERT(otn);

    event_id++;

    TriggerResponses(p, otn);

    switch(rtn->type)
    {
        case RULE_PASS:
            PassAction();
            break;

        case RULE_ACTIVATE:
            ActivateAction(p, otn, &otn->event_data);
            break;

        case RULE_ALERT:
            AlertAction(p, otn, &otn->event_data);
            break;

        case RULE_DYNAMIC:
            DynamicAction(p, otn, &otn->event_data);
            break;

        case RULE_LOG:
            LogAction(p, otn, &otn->event_data);
            break;

        case RULE_DROP:
            DropAction(p, otn, &otn->event_data);
            break;

#ifdef GIDS
        case RULE_SDROP:
            SDropAction(p, otn, &otn->event_data);
            break;

        case RULE_REJECT:
            RejectAction(p, otn, &otn->event_data);
            break;
#endif /* GIDS */
    }

    SetTags(p, otn, event_id);

    if(rtn->type != RULE_PASS)
    {
        check_tags_flag = 0;
    }

    p->packet_flags &= ~PKT_INLINE_DROP;

    otn_tmp = NULL;

    return 0;
}

/*
**
**  NAME
**    InitMatchInfo::
**
**  DESCRIPTION
**    Initialize the OTNX_MATCH_DATA structure.  We do this for
**    every packet so calloc is not used as this would zero the
**    whole space and this only sets the necessary counters to
**    zero, and saves us time.
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA * - pointer to structure to init.
**
**  FORMAL OUTPUT
**    None
**
*/
static INLINE void InitMatchInfo(OTNX_MATCH_DATA *o)
{
    int i = 0;

    for(i = 0; i < o->iMatchInfoArraySize; i++)
    {
        o->matchInfo[i].iMatchCount  = 0;
        o->matchInfo[i].iMatchIndex  = 0;
        o->matchInfo[i].iMatchMaxLen = 0;
    }
}

/*
**
**  NAME
**    fpAddMatch::
**
**  DESCRIPTION
**    Add and Event to the appropriate Match Queue: Alert, Pass, or Log.
**    This allows us to find multiple events per packet and pick the 'best'
**    one.  This function also allows us to change the order of alert,
**    pass, and log signatures by cacheing them for decision later.
**
**    IMPORTANT NOTE:
**    fpAddMatch must be called even when the queue has been maxed
**    out.  This is because there are three different queues (alert,
**    pass, log) and unless all three are filled (or at least the 
**    queue that is in the highest priority), events must be looked
**    at to see if they are members of a queue that is not maxed out.
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA    * - the omd to add the event to.
**    OTNX               * - the otnx to add.
**    int pLen             - length of pattern that matched, 0 for no content
**
**  FORMAL OUTPUTS
**    int - 1 max_events variable hit, 0 successful.
**
*/
static INLINE int fpAddMatch(OTNX_MATCH_DATA *omd, OTNX *otnx, int pLen )
{
    MATCH_INFO * pmi;
    int evalIndex;

    evalIndex = otnx->otn->rtn->listhead->ruleListNode->evalIndex;
   
    /* bounds check index */
    if( evalIndex >= omd->iMatchInfoArraySize )
        return 1;

    pmi = &omd->matchInfo[evalIndex];

    /*
    **  If we hit the max number of unique events for any rule type alert,
    **  log or pass, then we don't add it to the list.
    */
    if( pmi->iMatchCount >= fpDetect->max_queue_events || 
        pmi->iMatchCount >= MAX_EVENT_MATCH)
    {
        return 1;
    }

    /*
    **  Add the event to the appropriate list
    **  Warning: C6386 is a false positive dues to bounds check above.:427
    */
    pmi->MatchArray[ pmi->iMatchCount ] = otnx;

    /*
    **  This means that we are adding a NC rule
    **  and we only set the index to this rule
    **  if there is no content rules in the
    **  same array.
    */
    if(pLen > 0)
    {
        /*
        **  Event Comparison Function
        **  Here the largest content match is the
        **  priority
        */
        if( pmi->iMatchMaxLen < pLen )
        {
            pmi->iMatchMaxLen = pLen;
            pmi->iMatchIndex  = pmi->iMatchCount;
        }
    }

    pmi->iMatchCount++;
  
    return 0;
}

/*
**
**  NAME
**    fpEvalOTN::
**
**  DESCRIPTION
**    Evaluates an OTN against a Packet.
**
**  FORMAL INPUTS
**    OptTreeNode * - the OTN to check
**    Packet *      - Packet to evaluate against OTN
**
**  FORMAL OUTPUT
**    int - 0 if no match, 1 if match.
**
*/
static INLINE int fpEvalOTN(OptTreeNode *List, Packet *p)
{
    PROFILE_VARS;

    if(List == NULL)
        return 0;

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   => Checking SID %d\n",
               List->sigInfo.id););

    if(List->type == RULE_DYNAMIC && !List->active_flag)
    {
        return 0;
    }

    if(List->opt_func == NULL)
    {
        FatalError("List->opt_func was NULL on option #%d!\n", 
                List->chain_node_number);
    }

    if(snort_runtime.capabilities.stateful_inspection == 1)
    {
        if((List->established == 1) && !(p->packet_flags & PKT_STREAM_EST))
        {
            /*
            **  We check to see if this packet may have been picked up in
            **  midstream by stream4 on a timed out session.  If it was, then
            **  we'll go ahead and inspect it anyway because it might be a 
            **  packet that we dropped but the attacker has retransmitted after
            **  the stream4 session timed out.
            */
            if(InlineMode())
            {
                switch(List->rtn->type)
                {
                    case RULE_DROP:
                    case RULE_SDROP:
                        
                        if(stream_api && 
			   !(stream_api->get_session_flags(p->ssnptr) & SSNFLAG_MIDSTREAM))
                        {
                            return 0;
                        }
                        break;

                    default:
                        return 0;
                }
            }
            else
            {
                /* 
                ** This OTN requires an established connection and it isn't
                ** in that state yet, so continue to the next OTN
                */
                return 0;
            }
        }
        else if((List->unestablished == 1) && (p->packet_flags & PKT_STREAM_EST))
        {
            /*
            **  We're looking for an unestablished stream, and this is
            **  established, so don't continue processing.
            */
            return 0;
        }
    }

    OTN_PROFILE_START(List);

    if(!List->opt_func->OptTestFunc(p, List, List->opt_func))
    {
#ifdef PERF_PROFILING
        /* Handle the case where flowbits:noalert returns 0 to here
         * but there was actually a match. */
        if (List->noalerts)
        {
            OTN_PROFILE_END_MATCH(List);
        }
        else
        {
            OTN_PROFILE_END_NOMATCH(List);
        }
#endif
        return 0;
    }
            
    OTN_PROFILE_END_MATCH(List);

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
             "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   => SID %d OTN Matched!\n",
                List->sigInfo.id););
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
            "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n"););
    /* 
    ** Rule match actions are called from EvalHeader. 
    */
    return 1;
}

/*
**
**  NAME
**    fpEvalRTN::
**
**  DESCRIPTION
**    Evaluates an RTN against a packet.  We can probably get rid of
**    the check_ports variable, but it's in there for good luck.  :)
**
**  FORMAL INPUTS
**    RuleTreeNode * - RTN to check packet against.
**    Packet       * - Packet to evaluate
**    int            - whether to do a quick enhancement against ports.
**
**  FORMAL OUTPUT
**    int - 1 if match, 0 if match failed.
**
*/
static INLINE int fpEvalRTN(RuleTreeNode *rtn, Packet *p, int check_ports)
{
    if(rtn == NULL)
    {
        return 0;
    }

    /*
    **  This used to be a speed improvement.  Might still be.
    */
    if(check_ports)
    {
        if(!(rtn->flags & EXCEPT_DST_PORT) && !(rtn->flags & BIDIRECTIONAL) &&
                (p->dp < rtn->ldp))
        {
            return 0;
        }
    }

    if(rtn->type == RULE_DYNAMIC)
    {
        if(!active_dynamic_nodes)
        {
            return 0;
        }

        if(rtn->active_flag == 0)
        {
            return 0;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "[*] Rule Head %d\n", 
                rtn->head_node_number);)

    if(!rtn->rule_func->RuleHeadFunc(p, rtn, rtn->rule_func))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                    "   => Header check failed, checking next node\n"););
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
                    "   => returned from next node check\n"););
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
             "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   => RTN %d Matched!\n",
                rtn->head_node_number););
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
            "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n"););
    /*
    **  Return that there is a rule match and log the event outside
    **  of this routine.
    */
    return 1;
}

/*
**  NAME
**    fpEvalRTNSW::
**
**  DESCRIPTION
**    This function checks the RTN for validation first and then checks the
**    OTN for a pattern match.
**  
**  FORMAL INPUTS
**    RuleTreeNode * - rtn to inspect packet against
**    OptTreeNode *  - otn to inspect packet against
**    Packet *       - packet to inspect against
**    int            - whether to check ports for this packet
**
**  FORMAL OUTPUTS
**    int - 1 is successful match
**          0 is no match
**
*/
static INLINE int fpEvalRTNSW(RuleTreeNode *rtn, OptTreeNode *otn, Packet *p, int check_ports)
{
    /*
    **  This is set to one, because we already have
    **  an OTN hit.
    */
    int rule_match = 0;

    /*
    **  Reset the last match offset for each OTN we touch... 
    */
    doe_ptr = NULL;


    if(rtn == NULL)
    {
        return 0;
    }

    /*
    **  Used to be a speed optimization.  Might still be.
    */
    if(check_ports)
    {
        if(!(rtn->flags & EXCEPT_DST_PORT) && !(rtn->flags & BIDIRECTIONAL) &&
                (p->dp < rtn->ldp))
        {
            return 0;
        }
    }

    if(rtn->type == RULE_DYNAMIC)
    {
        if(!active_dynamic_nodes)
        {
            return 0;
        }

        if(rtn->active_flag == 0)
        {
            return 0;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "[*] Rule Head %d\n", 
                rtn->head_node_number);)

    if(!rtn->rule_func->RuleHeadFunc(p, rtn, rtn->rule_func))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                    "   => Header check failed, checking next node\n"););
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
                    "   => returned from next node check\n"););
        return 0;
    }

    /*
    **  RTN is validated, now check the OTN.
    */
    rule_match = fpEvalOTN(otn, p);

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
             "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   => RTN %d Matched!\n",
                rtn->head_node_number););
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
            "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n"););
    return rule_match;
}

/*
**
**  NAME
**    otnx_match::
**
**  DESCRIPTION
**    When the pattern matcher finds a match, this routine
**    is processed.  The match is checked to see whether the
**    associated otn and rtn have already been validated for
**    this packet, and if so does not do the check again.
**    Otherwise, the otn/rtn validation occurs.
**
**  FORMAL INPUTS
**
**    unsigned  id              : users first handle/ptr-whatever to this pattern
**    unsigned  id2             : users 2nd data 
**    int index                 : index in packet data
**    void *data                : user data passed in when pattern was loaded
**
**  FORMAL OUTPUT
**    int 0 - continue processing
**        1 - stop processing this packet for patterns
**
*/
static int otnx_match( void * id, int index, void * data)
{
    OTNX_MATCH_DATA  *omd    = (OTNX_MATCH_DATA *)data;
    PMX              *pmx    = (PMX*)id;
    RULE_NODE        *rnNode = (RULE_NODE*)(pmx->RuleNode);

    OTNX             *otnx   = (OTNX*)(rnNode->rnRuleData);
    PatternMatchData *pmd    = (PatternMatchData*)pmx->PatternMatchData;
    PROFILE_VARS;

    /* set up the current otn pointer for the exception handler */
    current_otn = otnx->otn;

    PREPROC_PROFILE_START(rulePerfStats);
    /*
    **  This is where we check the RULE_NODE ID for
    **  previous hits.
    */
    if(boIsBitSet(&(omd->pg->boRuleNodeID), rnNode->iRuleNodeID))
    {
        current_otn = 0;
        PREPROC_PROFILE_END(rulePerfStats);
        return 0;
    }

    if( fpEvalRTNSW(otnx->rtn, otnx->otn, omd->p, omd->check_ports) )
    {
        /*
        **  We have a qualified event
        */
        omd->pg->pgQEvents++;
        UpdateQEvents();

        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
                "[**] SID %d added to event queue [**]\n", 
                otnx->otn->sigInfo.id););

        fpAddMatch(omd, otnx, pmd->pattern_size );
    }
    else
    {
        /*
        ** This means that the event is non-qualified.
        */
        omd->pg->pgNQEvents++;
        UpdateNQEvents();
    }
     
    /*
    **  Here is where we set the bit array for each RULE_NODE that
    **  we hit.
    */
    if ( !otnx->otn->failedCheckBits )
    {
        if(boSetBit(&(omd->pg->boRuleNodeID), rnNode->iRuleNodeID))
        {
            /*
            **  There was an error, don't do anything right now.
            */
        }   
    }
    else
    {
        otnx->otn->failedCheckBits = 0;
    }

    PREPROC_PROFILE_END(rulePerfStats);

    current_otn = 0;

    return 0;
}

static int sortOrderByPriority(const void *e1, const void *e2)
{
    OTNX *o1;
    OTNX *o2;

    if(!e1 || !e2)
        return 0;

    o1 = *(OTNX **)e1;
    o2 = *(OTNX **)e2;

    if( o1->otn->sigInfo.priority < o2->otn->sigInfo.priority )
        return +1;

    if( o1->otn->sigInfo.priority > o2->otn->sigInfo.priority )
        return -1;

    return 0;
}

static int sortOrderByContentLength(const void *e1, const void *e2)
{
    OTNX      *o1;
    OTNX      *o2;

    if(!e1 || !e2)
        return 0;

    o1 = *(OTNX **)e1;
    o2 = *(OTNX **)e2;

    if( !o1 || !o2 )
        return 0;

#ifdef XXXX
    if(!e1->rule_info && e2->rule_info)
    {
        /*
        **  incoming event is not a rule, keep
        **  looking.
        */
        return -1;
    }
    else if(e1->rule_info && !e2->rule_info)
    {
        /*
        **  incoming event is a rule, event in queue
        **  is not.  Put incoming here.
        */
        return +1;
    }
    else if(!e1->rule_info && !e2->rule_info)
    {
        /*
        **  Neither event is a rule.  Use incoming as
        **  priority.  Last one in goes at the end to
        **  preserve rule order.
        */
        return 0;
    }
#endif
    /*
    **  We already know that these pointers aren't NULL by
    **  the previous logic.
    */

    if(o1->content_length < o2->content_length)
        return +1;

    if(o1->content_length > o2->content_length)
        return -1;

    return 0;
}


/*
**
**  NAME
**    fpFinalSelectEvent::
**
**  DESCRIPTION
**    fpFinalSelectEvent is called at the end of packet processing
**    to decide, if there hasn't already been a selection, to decide
**    what event to select.  This function is different from 
**    fpSelectEvent by the fact that fpSelectEvent only selects an
**    event if it is the first priority setting (drop/pass/alert...).
**
**    We also loop through the events we log, so that we don't log the
**    same event twice.  This can happen with unique conflicts some
**    of the time.
**
**    IMPORTANT NOTE:
**    We call fpFinalSelectEvent() after all processing of the packet
**    has been completed.  The reason this must be called afterwards is
**    because of unique rule group conflicts for a packet.  If there is
**    a unique conflict, then we inspect both rule groups and do the final
**    event select after both rule groups have been inspected.  The
**    problem came up with bi-directional rules with pass rule ordering
**    as the first type of rule.  Before we would detect a alert rule in
**    the first rule group, and since there was no pass rules we would
**    log that alert rule.  However, if we had inspected the second rule
**    group, we would have found a pass rule and that should have taken
**    precedence.  We now inspect both rule groups before doing a final
**    event select.
**
**    NOTES
**    Jan 2006 : marc norton
**    Previously it was possible to not log all desired events, if for
**    instance the rule order was alert->drop in inline mode we would
**    alert but no drop.  The default ordering of 'drop alert pass log ...'
**    normally handles this, however, it could happen.  Also, in the
**    default ordering alerts on the same packet a drop was applied to
**    did not get logged. To be more flexible and handle all manners of
**    subjective rule ordering and logging desired by the whole farm we've
**    changed things a bit.
**
**    Now, each actions event list is processed in order, based on the rule
**    order.  We process all events up to the log limit specified via the
**    'config event_queue: ...' as you might expect.  Pass rules are
**    handled a bit differently. As soon as a pass rule based event is
**    processed in the event queue, we stop processing any further events
**    on the packet if the pass event is the 1st ordering that sees an
**    event.  Otherwise if the ordering has it that pass rule events are
**    processed after a drop or alert you will see the drops and alerts,
**    and the pass event just causes us to stop processing any more events
**    on the packet, but the packet does not pass.  Also, the --alert-on-drop
**    flag causes any drop/sdrop/reject rules to be loaded as alert rules.
**    The default has been to ignore them on parsing.
**
**    If this is less than clear, herese the $.02 version:
**    default order -> pass drop alert log ( --alert-before-pass reverts
**    to -> drop alert pass log ) the 1st action-type of events in the rule
**    ordering to be seen gets logged by default the --flush-all-events
**    flag will cause secondary and tertiary action-events to be logged.
**    the -o flag is useless, but accepted, for now.
**    the max_events and log fields are reduced to only needing the log
**    events field. max_fields is harmless.
**    ( drop rules may be honored as alerts in IDS mode (no -Q) by using
**    the --alert-on-drop flag )
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA * - omd to select event from.
**    Packet *          - pointer to packet to log.
**
**  FORMAL OUTPUT
**    int - return 0 if no match, 1 if match.
**   
*/
static INLINE int fpFinalSelectEvent(OTNX_MATCH_DATA *o, Packet *p)
{
    int i;
    int j;
    int k;
    OTNX *otnx;
    int   tcnt=0;

    for( i = 0; i < o->iMatchInfoArraySize; i++ )
    {
        /* bail if were not dumping events in all the action groups,
         * and we've alresady got some events */
        if( ( g_event_queue.process_all_events == 0 && pv.process_all_events == 0 ) && tcnt > 0 )
            return 1;

        if(o->matchInfo[i].iMatchCount)
        {
            /*
             * We must always sort so if we que 8 and log 3 and they are
             * all from the same action group we want them sorted so we get
             * the highest 3 in priority, priority and lenght sort do NOT
             * take precedence over 'alert drop pass ...' ordering.  If
             * order is 'drop alert', and we log 3 for drop alertsdo not
             * get logged.  IF order is 'alert drop', and we log 3 for
             * alert, than no drops are logged.  So, there should be a
             * built in drop/sdrop/reject comes before alert/pass/log as
             * part of the natural ordering....Jan '06..
             */
            /* Sort the rules in this action group */
            if(g_event_queue.order == SNORT_EVENTQ_PRIORITY)
            {
                qsort(o->matchInfo[i].MatchArray,o->matchInfo[i].iMatchCount,sizeof(void*),sortOrderByPriority);
            }
            else if(g_event_queue.order == SNORT_EVENTQ_CONTENT_LEN)
            {
                qsort(o->matchInfo[i].MatchArray,o->matchInfo[i].iMatchCount,sizeof(void*),sortOrderByContentLength);
            }
            else
            {
                FatalError("fpdetect: Order function for event queue is invalid.\n");
            }

            /* Process each event in the action (alert,drop,log,...) groups */
            for(j=0; j < o->matchInfo[i].iMatchCount; j++)
            {
                otnx = o->matchInfo[i].MatchArray[j];

                if( otnx && otnx->otn && (otnx->otn->type == RULE_PASS) )
                {
                    /* Already acted on rules, so just don't act on anymore */
                    if( tcnt > 0 )
                        return 1;
                }

                /*
                **  Loop here so we don't log the same event
                **  multiple times.
                */
                for(k = 0; k < j; k++)
                {
                    if(o->matchInfo[i].MatchArray[k] == otnx)
                    {
                        otnx = NULL; 
                        break;
                    }
                }

                if( otnx && otnx->otn && !fpSessionAlerted(p, otnx) &&
                   !fpFragAlerted(p, otnx))
                {
                    /*
                    **  QueueEvent
                    */
                    SnortEventqAdd(otnx->otn->sigInfo.generator, 
                                   otnx->otn->sigInfo.id,
                                   otnx->otn->sigInfo.rev,
                                   otnx->otn->sigInfo.class_id,
                                   otnx->otn->sigInfo.priority,
                                   otnx->otn->sigInfo.message,
                                   (void *)otnx);
                    tcnt++;
                }
                
                if ( p->ssnptr )
                {                     
                    fpAddSessionAlert(p, otnx);
                }

                if ( p->fragtracker )
                {
                    fpAddFragAlert(p, otnx);
                }

                if( tcnt >= g_event_queue.log_events )
                    return 1;

                /* only log/count one pass */
                if( otnx &&  otnx->otn && (otnx->otn->type == RULE_PASS) )
                {
                    p->packet_flags |= PKT_PASS_RULE;
                    return 1;
                }
            }
        }
    }

    return 0;
}

/*
**  
**  NAME
**    fpAddSessionAlert::
**
**  DESCRIPTION
**    This function flags an alert per session.
**
**  FORMAL INPUTS
**    Packet *     - the packet to inspect
**    OTNX *       - the rule that generated the alert
**
**  FORMAL OUTPUTS
**    int - 0 if not flagged
**          1 if flagged
**
*/
static INLINE int fpAddSessionAlert(Packet *p, OTNX *otnx)
{
    if ( !p->ssnptr )
        return 0;

    if ( !otnx )
        return 0;

    if ( !otnx->otn )
        return 0;

    /* Only track a certain number of alerts per session */
    if (stream_api)
        return !stream_api->add_session_alert(p->ssnptr, p,
                                  otnx->otn->sigInfo.generator,
                                  otnx->otn->sigInfo.id);
    return 0;
}

/*
**  
**  NAME
**    fpSessionAlerted::
**
**  DESCRIPTION
**    This function indicates whether or not an alert has been generated previously
**    in this session, but only if this is a rebuilt packet.
**
**  FORMAL INPUTS
**    Packet *     - the packet to inspect
**    OTNX *       - the rule that generated the alert
**
**  FORMAL OUTPUTS
**    int - 0 if alert NOT previously generated
**          1 if alert previously generated
**
*/
static INLINE int fpSessionAlerted(Packet *p, OTNX *otnx)
{
    SigInfo *si = &otnx->otn->sigInfo;

    if ( !stream_api )
        return 0;

    if (!stream_api->check_session_alerted(p->ssnptr, p, si->generator, si->id))
        return 0;
    else
        return 1;

}


/*
**  fpEvalHeader::
**
**  This function is the old way of walking PORT_GROUPs.  We
**  check the OTNs for matches and then check the RTN for
**  validation if the OTN matches.
**  Kept for backwards-compatibility
*/
static INLINE int fpEvalHeader(PORT_GROUP *port_group, Packet *p, int check_ports)
{
    RULE_NODE *rnWalk;
    OTNX *otnxWalk;

    /*
    **  Walk the content OTNs
    */
    for(rnWalk = port_group->pgHead; rnWalk; rnWalk = rnWalk->rnNext)
    {
        /*
        **  Reset the last match offset for each OTN we touch... 
        */
        doe_ptr = NULL;
        
        otnxWalk = (OTNX *)rnWalk->rnRuleData;
        /*
        **  Do the OTN check, if successful than we check
        **  the RTN for validation purposes.
        */
        if(fpEvalOTN(otnxWalk->otn, p))
        {
            /*
            **  OTN is match, check RTN
            */
            if(fpEvalRTN(otnxWalk->rtn, p, check_ports))
            {
                fpLogEvent(otnxWalk->rtn, otnxWalk->otn, p);
                return 1;
            }
            
            continue;
        }
    }

    /*
    **  Walk the non-content OTNs
    */
    for(rnWalk = port_group->pgHeadNC; rnWalk; rnWalk = rnWalk->rnNext)
    {
        /*
        **  Reset the last match offset for each OTN we touch... 
        */
        doe_ptr = NULL;

        otnxWalk = (OTNX *)rnWalk->rnRuleData;
        /*
        **  Do the OTN check, if successful than we check
        **  the RTN for validation purposes.
        */
        if(fpEvalOTN(otnxWalk->otn, p))
        {
            /*
            **  OTN is match, check RTN
            */
            if(fpEvalRTN(otnxWalk->rtn, p, check_ports))
            {
                fpLogEvent(otnxWalk->rtn, otnxWalk->otn, p);
                return 1;
            }
            
            continue;
        }
    }

    return 0;
}

/*
**  
**  NAME
**    fpEvalHeaderSW::
**
**  DESCRIPTION
**    This function does a set-wise match on content, and walks an otn list
**    for non-content.  The otn list search will eventually be redone for 
**    for performance purposes.
**
**  FORMAL INPUTS
**    PORT_GROUP * - the port group to inspect
**    Packet *     - the packet to inspect
**    int          - whether src/dst ports should be checked (udp/tcp or icmp)
**
**  FORMAL OUTPUTS
**    int - 0 for failed pattern match
**          1 for sucessful pattern match
**
*/
static INLINE int fpEvalHeaderSW(PORT_GROUP *port_group, Packet *p, int check_ports)
{
    RULE_NODE *rnWalk;
    OTNX *otnx = NULL;
    void * so;
    
    /* XXX it is not a good idea to allocate memory here */
 
    extern HttpUri  UriBufs[URI_COUNT]; /* decode.c */

    /*
    **  Init the info for rule ordering selection
    */
    //InitMatchInfo( &omd );
    
    if (do_detect_content)
    {
        /*
        **  PKT_STREAM_INSERT packets are being rebuilt and re-injected
        **  through this detection engine.  So in order to avoid pattern
        **  matching bytes twice, we wait until the PKT_STREAM_INSERT 
        **  packets are rebuilt and injected through the detection engine.
        **
        **  PROBLEM:
        **  If a stream gets stomped on before it gets re-injected, an attack
        **  would be missed.  So before a connection gets stomped, we 
        **  re-inject the stream we have.
        */
        if(fpDetect->inspect_stream_insert || 
           !(p->packet_flags & PKT_STREAM_INSERT))
        {
            /*
            **   Uri-Content Match
            **   This check indicates that http_decode found
            **   at least one uri
            */
            if( p->uri_count > 0)
            {
                int i;
                so = (void *)port_group->pgPatDataUri;
    
                if( so ) /* Do we have any URI rules ? */
                {
                    mpseSetRuleMask( so, &port_group->boRuleNodeID ); 
    
                    /*
                    **  Process all of the packet's URIs
                    */
                    for( i=0; i<p->uri_count; i++)
                    {
                        if(UriBufs[i].uri == NULL)
                            continue;
    
                        omd.pg = port_group;
                        omd.p  = p;
                        omd.check_ports= check_ports;
    
                        mpseSearch (so, UriBufs[i].uri, UriBufs[i].length, 
                             otnx_match, &omd);
                    }   
                }
            }
    
            /*
            **  If this is a pipeline request don't do the no-content
            **  rules since we already checked them during the
            **  first URI inspection.
            */
            if(UriBufs[0].decode_flags & HTTPURI_PIPELINE_REQ)
            {
                boResetBITOP(&(port_group->boRuleNodeID));
                return 0;
            }
    
            /*
            **  Decode Content Match
            **  We check to see if the packet has been normalized into
            **  the global (decode.c) DecodeBuffer.  Currently, only
            **  telnet normalization writes to this buffer.  So, if
            **  it is set, we do this the match against the normalized
            **  buffer and we do the check against the original 
            **  payload, in case any of the rules have the 
            **  'rawbytes' option.
            */
            so = (void *)port_group->pgPatData;
    
            if((p->packet_flags & PKT_ALT_DECODE) && so && p->alt_dsize) 
            {
                mpseSetRuleMask( so, &port_group->boRuleNodeID ); 
    
                omd.pg = port_group;
                omd.p = p;
                omd.check_ports= check_ports;
    
                mpseSearch ( so, DecodeBuffer, p->alt_dsize, 
                        otnx_match, &omd );
    
                /*
                 **  The reason that we reset the bitops is because
                 **  an OTN might not be verified using the DecodeBuffer
                 **  because of the 'rawbytes' option, while the next pass
                 **  will need to validate that same rule in the case
                 **  of rawbytes.
                 */
                boResetBITOP(&(port_group->boRuleNodeID));
            }
            
            /*
            **  Content-Match - If no Uri-Content matches, than do a Content search
            **
            **  NOTE:
            **    We may want to bail after the Content search if there
            **    has been a successful match.
            */
            if( so && p->data && p->dsize) 
            {
                mpseSetRuleMask( so, &port_group->boRuleNodeID ); 
    
                omd.pg = port_group;
                omd.p = p;
                omd.check_ports= check_ports;
    
                mpseSearch ( so, p->data, p->dsize, otnx_match, &omd );
            }
    
            boResetBITOP(&(port_group->boRuleNodeID));
        }
    }

    /*
    **  PKT_REBUILT_STREAM packets are re-injected streams.  This means
    **  that the "packet headers" are completely bogus and only the 
    **  content matches are important.  So for PKT_REBUILT_STREAMs, we
    **  don't inspect against no-content OTNs since these deal with 
    **  packet headers, packet sizes, etc.
    **
    **  NOTE:
    **  This has been changed when evaluating no-content rules because
    **  it was interfering with the pass->alert ordering.  We still
    **  need to check no-contents against rebuilt packets, because of
    **  this problem.  Immediate solution is to have the detection plugins
    **  bail if the rule should only be inspected against packets, a.k.a
    **  dsize checks.
    */

    /*
    **  Walk and test the non-content OTNs
    */
    for(rnWalk = port_group->pgHeadNC; rnWalk; rnWalk = rnWalk->rnNext)
    {
        /*
        **  Reset the last match offset for each OTN we touch... 
        */
        doe_ptr = NULL;

        otnx = (OTNX *)rnWalk->rnRuleData;
        /*
        **  Do the OTN check, if successful than we check
        **  the RTN for validation purposes.
        */
        if(fpEvalOTN(otnx->otn, p))
        {
            /*
            *  OTN is match, check RTN
            */
            if(fpEvalRTN(otnx->rtn, p, check_ports))
            {
                port_group->pgQEvents++;
                UpdateQEvents();

                /*
                **  If the array if filled for this type
                **  of event, then it wasn't added and there
                **  is no reason to select the events again.
                */
                if( fpAddMatch(&omd, otnx, 0) )
                {
                    continue;
                }
            }
            else
            {
                /*
                **  This is a non-qualified event
                */
                port_group->pgNQEvents++;
                UpdateNQEvents();
            }

            continue;
        }
    }

    return 0;
}

/*
** fpEvalHeaderUdp::
*/
static INLINE int fpEvalHeaderUdp(Packet *p)
{
    PORT_GROUP *src, *dst, *gen;
    int retval;

    retval = prmFindRuleGroupUdp(p->dp, p->sp, &src, &dst, &gen);
  
    switch(retval)
    {
        case 0:
            /* nothing */
            return 0;
        case 1:
            InitMatchInfo( &omd );
            
            /* destination groups */
            if(fpEvalHeaderSW(dst, p, 1))
            {
                return 1;
            }
            break;
        case 2:
            InitMatchInfo( &omd );
            
            /*  source groups */
            if(fpEvalHeaderSW(src, p, 1))
            {
                return 1;
            }
            break;
        case 3:
            InitMatchInfo( &omd );
            
            /*  both ports */
            if(fpEvalHeaderSW(dst, p, 1))
            {
                return 1;
            }
            if(fpEvalHeaderSW(src, p, 1))
            {
                return 1;
            }
            break;
        case 4:
            InitMatchInfo( &omd );
            
            /*  generic */
            if(fpEvalHeaderSW(gen, p, 1))
            {
                return 1;
            }
            break;
        default:
            return 0;
    }

    return fpFinalSelectEvent(&omd, p);
}

/*
**  fpEvalHeaderTcp::
*/
static INLINE int fpEvalHeaderTcp(Packet *p)
{
    PORT_GROUP *src, *dst, *gen;
    int retval;

    retval = prmFindRuleGroupTcp(p->dp, p->sp, &src, &dst, &gen);
 
    switch(retval)
    {
        case 0:
            /* nothing */
            return 0;
        case 1:
            InitMatchInfo( &omd );
            
            /* destination groups */
            if(fpEvalHeaderSW(dst, p, 1))
            {
                return 1;
            }
            break;
        case 2:
            InitMatchInfo( &omd );

            /* source groups */
            if(fpEvalHeaderSW(src, p, 1))
            {
                return 1;
            }
            break;
        case 3:
            InitMatchInfo( &omd );

            /*  both ports */
            if(fpEvalHeaderSW(dst, p, 1))
            {
                return 1;
            }
            if(fpEvalHeaderSW(src, p, 1))
            {
                return 1;
            }
            break;
        case 4:
            InitMatchInfo( &omd );

            /*  generic */
            if(fpEvalHeaderSW(gen, p, 1))
            {
                return 1;
            }
            break;
        default:
            return 0;
    }

    return fpFinalSelectEvent(&omd, p);
}

/*
**  fpEvalHeaderICMP::
*/
static INLINE int fpEvalHeaderIcmp(Packet *p)
{
    PORT_GROUP *gen, *type;
    int retval;

    retval = prmFindRuleGroupIcmp(p->icmph->type, &type, &gen);
 
    switch(retval)
    {
        case 0:
            return 0;
        case 1:
            InitMatchInfo( &omd );
            
            /* icmp type */
#ifdef FPSW
            if(fpEvalHeaderSW(type, p, 0))
#else
            if(fpEvalHeader(type, p, 0))
#endif
            {
                return 1;
            }

            break;
        case 2:
            return 0;
        case 3:
            return 0;
        case 4:
            InitMatchInfo( &omd );
            
            /*  generic */
#ifdef FPSW
            if(fpEvalHeaderSW(gen, p, 0))
#else
            if(fpEvalHeader(gen, p, 0))
#endif
            {
                return 1;
            }

            break;
        default:
            return 0;
    }

    return fpFinalSelectEvent(&omd, p);
}

/*
**  fpEvalHeaderIP::
*/
static INLINE int fpEvalHeaderIp(Packet *p, int ip_proto)
{
    PORT_GROUP *gen, *ip_group;
    int retval;

    retval = prmFindRuleGroupIp(ip_proto, &ip_group, &gen);
 
    switch(retval)
    {
        case 0:
            return 0;
        case 1:
            InitMatchInfo( &omd );
            
            /* ip_group */
#ifdef FPSW
            if(fpEvalHeaderSW(ip_group, p, 0))
#else
            if(fpEvalHeader(ip_group, p, 0))
#endif
            {
                return 1;
            }

            break;
        case 2:
            return 0;
        case 3:
            return 0;
        case 4:
            InitMatchInfo( &omd );
            
            /* generic */
#ifdef FPSW
            if(fpEvalHeaderSW(gen, p, 0))
#else
            if(fpEvalHeader(gen, p, 0))
#endif
            {
                return 1;
            }

            break;

        default:
            return 0;
    }

    return fpFinalSelectEvent(&omd, p);
}

/*
**
**  NAME
**    fpEvalPacket::
**
**  DESCRIPTION
**    This function is the interface to the Detect() routine.  Here 
**    the IP protocol is processed.  If it is TCP, UDP, or ICMP, we
**    process the both that particular ruleset and the IP ruleset
**    with in the fpEvalHeader for that protocol.  If the protocol
**    is not TCP, UDP, or ICMP, we just process the packet against
**    the IP rules at the end of the fpEvalPacket routine.  Since
**    we are using a setwise methodology for snort rules, both the
**    network layer rules and the transport layer rules are done
**    at the same time.  While this is not the best for modularity,
**    it is the best for performance, which is what we are working
**    on currently.
**
**  FORMAL INPUTS
**    Packet * - the packet to inspect
**
**  FORMAL OUTPUT
**    int - 0 means that packet has been processed.
**
*/
int fpEvalPacket(Packet *p)
{
    int ip_proto = p->iph->ip_proto;

    switch(ip_proto)
    {
        case IPPROTO_TCP:
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
                        "Detecting on TcpList\n"););

            if(p->tcph == NULL)
            {
                ip_proto = -1;
                break;
            }

            return fpEvalHeaderTcp(p);

        case IPPROTO_UDP:
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
                        "Detecting on UdpList\n"););

            if(p->udph == NULL)
            {
                ip_proto = -1;
                break;
            }
            
            return fpEvalHeaderUdp(p);

        case IPPROTO_ICMP:
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
                        "Detecting on IcmpList\n"););

            if(p->icmph == NULL)
            {
                ip_proto = -1;
                break; 
            }

            return fpEvalHeaderIcmp(p);

        default:
            break;
    }

    /*
    **  No Match on TCP/UDP, Do IP
    */
    return fpEvalHeaderIp(p, ip_proto);
}

