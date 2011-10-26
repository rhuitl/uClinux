/*
**  $Id$
** 
**  fpcreate.c
**
**  Copyright (C) 2002 Sourcefire,Inc
**  Dan Roelker <droelker@sourcefire.com>
**  Marc Norton <mnorton@sourcefire.com>
**
**  NOTES
**  5.7.02 - Initial Checkin. Norton/Roelker
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
** 6/13/05 - marc norton
**   Added plugin support for fast pattern match data, requires DYNAMIC_PLUGIN be defined
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rules.h"
#include "parser.h"
#include "fpcreate.h"
#include "fpdetect.h"
#include "sp_pattern_match.h"
#include "sp_icmp_code_check.h"
#include "sp_icmp_type_check.h"
#include "sp_ip_proto.h"
#include "plugin_enum.h"
#include "util.h"
#include "rules.h"

#include "mpse.h"
#include "bitop_funcs.h"

#ifdef DYNAMIC_PLUGIN
#include "dynamic-plugins/sp_dynamic.h"
#endif

/*
#define LOCAL_DEBUG
*/

/*
**  Macro for verifying memory allocation and fail
**  accordingly.
*/
#define MEMASSERT(p,s) if(!p){printf("No memory - file:%s %s !\n",__FILE__,s); exit(1);}
/*
**  Main variables to this file. 
**
**  The port-rule-maps map the src-dst ports to rules for
**  udp and tcp, for Ip we map the dst port as the protocol, 
**  and for Icmp we map the dst port to the Icmp type. This 
**  allows us to use the decode packet information to in O(1) 
**  select a group of rules to apply to the packet.  These 
**  rules may have uricontent, content, or they may be no content 
**  rules, or any combination. We process the uricontent 1st,
**  than the content, and than the no content rules for udp/tcp 
**  and icmp, than we process the ip rules.
*/
static PORT_RULE_MAP *prmTcpRTNX = NULL;
static PORT_RULE_MAP *prmUdpRTNX = NULL;
static PORT_RULE_MAP *prmIpRTNX  = NULL;
static PORT_RULE_MAP *prmIcmpRTNX= NULL;

static FPDETECT fpDetect;

/*
**  The following functions are wrappers to the pcrm routines,
**  that utilize the variables that we have intialized by
**  calling fpCreateFastPacketDetection().  These functions
**  are also used in the file fpdetect.c, where we do lookups
**  on the initialized variables.
*/
int prmFindRuleGroupIp(int ip_proto, PORT_GROUP **ip_group, PORT_GROUP ** gen)
{
    PORT_GROUP *src;
    return prmFindRuleGroup( prmIpRTNX, ip_proto, -1, &src, ip_group, gen);
}

int prmFindRuleGroupIcmp(int type, PORT_GROUP **type_group, PORT_GROUP ** gen)
{
    PORT_GROUP *src;
    return prmFindRuleGroup( prmIcmpRTNX, type, -1, &src, type_group, gen);
}

int prmFindRuleGroupTcp(int dport, int sport, PORT_GROUP ** src, 
        PORT_GROUP **dst , PORT_GROUP ** gen)
{
    return prmFindRuleGroup( prmTcpRTNX, dport, sport, src, dst , gen);
}

int prmFindRuleGroupUdp(int dport, int sport, PORT_GROUP ** src, 
        PORT_GROUP **dst , PORT_GROUP ** gen)
{
    return prmFindRuleGroup( prmUdpRTNX, dport, sport, src, dst , gen);
}


/*
**  These Otnhas* functions check the otns for different contents.  This
**  helps us decide later what group (uri, content) the otn will go to.
*/
static int OtnHasContent( OptTreeNode * otn ) 
{
    if( !otn ) return 0;
    
    if( otn->ds_list[PLUGIN_PATTERN_MATCH] || otn->ds_list[PLUGIN_PATTERN_MATCH_OR] )
    {
        return 1; 
    }

#ifdef DYNAMIC_PLUGIN
    if (otn->ds_list[PLUGIN_DYNAMIC])
    {
        DynamicData *dd = (DynamicData *)otn->ds_list[PLUGIN_DYNAMIC];
        if (dd->fpContentFlags & FASTPATTERN_NORMAL)
            return 1;
    }
#endif

    return 0;
}

static int OtnHasUriContent( OptTreeNode * otn ) 
{
    if( !otn ) return 0;

    if( otn->ds_list[PLUGIN_PATTERN_MATCH_URI] )
        return 1; 

#ifdef DYNAMIC_PLUGIN
    if (otn->ds_list[PLUGIN_DYNAMIC])
    {
        DynamicData *dd = (DynamicData *)otn->ds_list[PLUGIN_DYNAMIC];
        if (dd->fpContentFlags & FASTPATTERN_URI)
            return 1;
    }
#endif

    return 0;
}

/*
**  
**  NAME
**    CheckPorts::
**
**  DESCRIPTION
**    This function returns the port to use for a given signature.
**    Currently, only signatures that have a unique port (meaning that
**    the port is singular and not a range) are added as specific 
**    ports to the port list.  If there is a range of ports in the
**    signature, then it is added as a generic rule.
**
**    This can be refined at any time, and limiting the number of
**    generic rules would be a good idea.
**
**  FORMAL INPUTS
**    u_short - the high port of the signature range
**    u_short - the low port of the signature range
**
**  FORMAL OUTPUT
**    int - -1 means generic, otherwise it is the port
**
*/
static int CheckPorts(u_short high_port, u_short low_port)
{
    if( high_port == low_port )
    {
       return high_port;
    }
    else
    {
       return -1;
    }
}

/*
**  The following functions deal with the intialization of the 
**  detection engine.  These are set through parser.c with the
**  option 'config detection:'.  This functionality may be 
**  broken out later into it's own file to separate from this
**  file's functionality.
*/

/*
**  Initialize detection options.
*/
int fpInitDetectionEngine()
{
    memset(&fpDetect, 0x00, sizeof(fpDetect));

    /*
    **  We inspect pkts that are going to be rebuilt and
    **  reinjected through snort.
    */
    fpDetect.inspect_stream_insert = 1;
    fpDetect.search_method = MPSE_ACF;
    fpDetect.search_method_verbose = 0;
    fpDetect.debug = 0;
    fpDetect.max_queue_events = 5;

    /*
    **  This functions gives fpdetect.c the detection configuration
    **  set up in fpcreate.
    */
    fpSetDetectionOptions(&fpDetect);

    return 0;
}

/*
   Search method is set using:
   config detect: search-method ac | ac-full | ac-sparsebands | ac-sparse | ac-banded | ac-std | verbose
*/
int fpSetDetectSearchMethod( char * method )
{
    LogMessage("Detection:\n");

    if( !strcasecmp(method,"ac-std") ) /* default */
    {
       fpDetect.search_method = MPSE_AC ;
       LogMessage("   Search-Method = AC-Std\n");
       return 0;
    }
    if( !strcasecmp(method,"ac-bnfa") )
    {
       fpDetect.search_method = MPSE_AC_BNFA ;
       LogMessage("   Search-Method = AC-BNFA\n");
       return 0;
    }
    if( !strcasecmp(method,"ac") )
    {
       fpDetect.search_method = MPSE_ACF ;
       LogMessage("   Search-Method = AC-Full\n");
       return 0;
    }
    if( !strcasecmp(method,"acs") )
    {
       fpDetect.search_method = MPSE_ACS ;
       LogMessage("   Search-Method = AC-Sparse\n");
       return 0;
    }
    if( !strcasecmp(method,"ac-banded") )
    {
       fpDetect.search_method = MPSE_ACB ;
       LogMessage("   Search-Method = AC-Banded\n");
       return 0;
    }
    if( !strcasecmp(method,"ac-sparsebands") )
    {
       fpDetect.search_method = MPSE_ACSB ;
       LogMessage("   Search-Method = AC-Sparse-Bands\n");
       return 0;
    }
        
    /* These are for backwards compatability - and will be removed in future releases*/

    if( !strcasecmp(method,"mwm") ) 
    {
       fpDetect.search_method = MPSE_LOWMEM ;
       LogMessage("   Search-Method = Low-Mem (MWM depracated)\n");
       return 0;
    }

    if( !strcasecmp(method,"lowmem") )
    {
       fpDetect.search_method = MPSE_LOWMEM ;
       LogMessage("   Search-Method = Low-Mem\n");
       return 0;
    }
    return 1;
}

/*
**  Set the debug mode for the detection engine.
*/
int fpSetDebugMode()
{
    fpDetect.debug = 1;
    return 0;
}

/*
**  Revert the detection engine back to not inspecting packets
**  that are going to be rebuilt.
*/
int fpSetStreamInsert()
{
    fpDetect.inspect_stream_insert = 0;
    return 0;
}

/*
**  Sets the maximum number of events to queue up in fpdetect before
**  selecting an event.
*/
int fpSetMaxQueueEvents(int iNum)
{
    if(iNum <= 0)
    {
        return 1;
    }

    fpDetect.max_queue_events = iNum;

    return 0;
}

/*
**  Build a Pattern group for the Uri-Content rules in this group
**
**  The patterns added for each rule must be suffcient so if we find any of them
**  we proceed to fully analyze the OTN and RTN against the packet.
**
*/
void BuildMultiPatGroupsUri( PORT_GROUP * pg )
{
    OptTreeNode      *otn;
    RuleTreeNode     *rtn;
    OTNX             *otnx; /* otnx->otn & otnx->rtn */
    PatternMatchData *pmd;
    RULE_NODE        *rnWalk = NULL;
    PMX              *pmx;
    void             *mpse_obj;
    int               method;
#ifdef DYNAMIC_PLUGIN
    DynamicData      *dd;
    FPContentInfo    *fplist[PLUGIN_MAX_FPLIST_SIZE];
#endif

    if(!pg || !pg->pgCount)
        return;
      
    /* test for any Content Rules */
    if( !prmGetFirstRuleUri(pg) )
        return;

    method = fpDetect.search_method;
    
    mpse_obj = mpseNew(method);
    MEMASSERT(mpse_obj,"BuildMultiPatGroupUri: mpse_obj=mpseNew");

    /*  
    **  Save the Multi-Pattern data structure for processing Uri's in this 
    **  group later during packet analysis.  
    */
    pg->pgPatDataUri = mpse_obj;
      
    /*
    **  Initialize the BITOP structure for this
    **  port group.  This is most likely going to be initialized
    **  by the non-uri BuildMultiPattGroup.  If for some reason there
    **  is only uri contents in a port group, then we miss the initialization
    **  in the content port groups and catch it here.
    */
    if( boInitBITOP(&(pg->boRuleNodeID),pg->pgCount) )
    {
        return;
    }

    /*
    *  Add in all of the URI contents, since these are effectively OR rules.
    *  
    */
    for( rnWalk=pg->pgUriHead; rnWalk; rnWalk=rnWalk->rnNext)
    {
        otnx = (OTNX *)rnWalk->rnRuleData;

        otn = otnx->otn;
        rtn = otnx->rtn;

        /* Add all of the URI contents */     
        pmd = otn->ds_list[PLUGIN_PATTERN_MATCH_URI];
        while( pmd )
        {
            if(pmd->pattern_buf) 
            {
               pmx = (PMX*)malloc(sizeof(PMX) );
               MEMASSERT(pmx,"pmx-uricontent");
               pmx->RuleNode    = rnWalk;
               pmx->PatternMatchData= pmd;

               /*
               **  Add the max content length to this otnx
               */
               if(otnx->content_length < pmd->pattern_size)
                   otnx->content_length = pmd->pattern_size;

                mpseAddPattern(mpse_obj, pmd->pattern_buf, pmd->pattern_size,
                pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
                pmd->offset,
                pmd->depth,
                pmx, //(unsigned)rnWalk,        /* rule ptr */ 
                //(unsigned)pmd,
                rnWalk->iRuleNodeID );
            }
            
            pmd = pmd->next;
        }
#ifdef DYNAMIC_PLUGIN
        /* 
        ** 
        ** Add in plugin contents for fast pattern matcher  
        **
        **/     
        dd =(DynamicData*) otn->ds_list[PLUGIN_DYNAMIC];
        if( dd )
        {
            int n,i;
            n = dd->fastPatternContents(dd->contextData,FASTPATTERN_URI,fplist,PLUGIN_MAX_FPLIST_SIZE);
        
            for(i=0;i<n;i++) 
            {
                pmd = (PatternMatchData*)malloc(sizeof(PatternMatchData) );
                MEMASSERT(pmd,"pmd-plugin-content");
            
                pmx = (PMX*)malloc(sizeof(PMX) );
                MEMASSERT(pmx,"pmx-plugin-content");
            
                pmx->RuleNode        = rnWalk;
                pmx->PatternMatchData= pmd;
            
                pmd->pattern_buf = fplist[i]->content;
                pmd->pattern_size= fplist[i]->length;
                pmd->nocase      = fplist[i]->noCaseFlag;
                pmd->offset      = 0;
                pmd->depth       = 0;
            
                mpseAddPattern( mpse_obj, 
                    pmd->pattern_buf, 
                    pmd->pattern_size,
                    pmd->nocase,  /* 1--NoCase, 0-Case */
                    pmd->offset,
                    pmd->depth,
                    pmx,  
                    rnWalk->iRuleNodeID );
            }
        }
#endif
    }

    mpsePrepPatterns( mpse_obj );
    if( fpDetect.debug ) mpsePrintInfo( mpse_obj );
}

/*
**
**   NAME
**     IsPureNotRule
**
**   DESCRIPTION
**     Checks to see if a rule is a pure not rule.  A pure not rule
**     is a rule that has all "not" contents or Uri contents.
**
**   FORMAL INPUTS
**     PatternMatchData * - the match data to check for not contents.
**
**   FORMAL OUTPUTS
**     int - 1 is rule is a pure not, 0 is rule is not a pure not.
**
*/
static int IsPureNotRule( PatternMatchData * pmd )
{
    int rcnt=0,ncnt=0;

    for( ;pmd; pmd=pmd->next )
    {
        rcnt++;
        if( pmd->exception_flag ) ncnt++;
    }

    if( !rcnt ) return 0;
    
    return ( rcnt == ncnt ) ;  
}

/*
**
**  NAME
**    FindLongestPattern
**
**  DESCRIPTION
**    This functions selects the longest pattern out of a set of
**    patterns per snort rule.  By picking the longest pattern, we
**    help the pattern matcher speed and the selection criteria during
**    detection.
**
**  FORMAL INPUTS
**    PatternMatchData * - contents to select largest
**
**  FORMAL OUTPUTS 
**    PatternMatchData * - ptr to largest pattern
**
*/
static PatternMatchData * FindLongestPattern( PatternMatchData * pmd )
{
    PatternMatchData *pmdmax;
   
    /* Find the 1st pattern that is not a NOT pattern */   
    while( pmd && pmd->exception_flag ) pmd=pmd->next;
        
    if( !pmd ) return NULL;  /* All Patterns are NOT patterns */
      
    pmdmax = pmd;

    while( pmd )
    {
        if(pmd->pattern_buf) 
        {
            if( (pmd->pattern_size > pmdmax->pattern_size) && 
                    !pmd->exception_flag)
            {
                pmdmax = pmd;
            }
        }
        pmd = pmd->next;
    }

    return pmdmax;
}

/*
*  Build Content-Pattern Information for this group
*/
void BuildMultiPatGroup( PORT_GROUP * pg )
{
    OptTreeNode      *otn;
    RuleTreeNode     *rtn;
    OTNX             *otnx; /* otnx->otn & otnx->rtn */
    PatternMatchData *pmd, *pmdmax;
    RULE_NODE        *rnWalk = NULL;
    PMX              *pmx;
    void             *mpse_obj;
    /*int maxpats; */
    int               method;
#ifdef DYNAMIC_PLUGIN
    DynamicData      *dd;
    FPContentInfo    *fplist[PLUGIN_MAX_FPLIST_SIZE];
#endif
    if(!pg || !pg->pgCount)
        return;
     
    /* test for any Content Rules */
    if( !prmGetFirstRule(pg) )
        return;
      
    method = fpDetect.search_method;

    mpse_obj = mpseNew( method );
    if(!mpse_obj) FatalError("BuildMultiPatGroup: memory error, mpseNew(%d) failed\n",fpDetect.search_method);
            
    /* Save the Multi-Pattern data structure for processing this group later 
       during packet analysis.
    */
    pg->pgPatData = mpse_obj;

    /*
    **  Initialize the BITOP structure for this
    **  port group.
    */
    if( boInitBITOP(&(pg->boRuleNodeID),pg->pgCount) )
    {
        return;
    }
      
    /*
    *  For each content rule, add one of the AND contents,
    *  and all of the OR contents
    */
    for(rnWalk=pg->pgHead; rnWalk; rnWalk=rnWalk->rnNext)
    {
        otnx = (OTNX *)(rnWalk->rnRuleData);

        otn = otnx->otn;
        rtn = otnx->rtn;

        /* Add the longest AND patterns, 'content:' patterns*/
        pmd = otn->ds_list[PLUGIN_PATTERN_MATCH];

        /*
        **  Add all the content's for the Pure Not rules, 
        **  because we will check after processing the packet
        **  to see if these pure not rules were hit using the
        **  bitop functionality.  If they were hit, then there
        **  is no event, otherwise there is an event.
        */
        if( pmd && IsPureNotRule( pmd ) )
        {
            /*
            **  Pure Not Rules are not supported.
            */
            LogMessage("SNORT DETECTION ENGINE: Pure Not Rule "
                       "'%s' not added to detection engine.  "
                       "These rules are not supported at this "
                       "time.\n", otn->sigInfo.message);

            while( pmd ) 
            {
                if( pmd->pattern_buf ) 
                {
                    pmx = (PMX*)malloc(sizeof(PMX) );
                    MEMASSERT(pmx,"pmx-!content");
                    pmx->RuleNode   = rnWalk;
                    pmx->PatternMatchData= pmd;

                    mpseAddPattern( mpse_obj, pmd->pattern_buf, 
                      pmd->pattern_size, 
                      pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
                      pmd->offset, 
                      pmd->depth,
                      pmx,  
                      rnWalk->iRuleNodeID );
                }

                pmd = pmd->next;
            }

            /* Build the list of pure NOT rules for this group */
            prmAddNotNode( pg, (int)rnWalk->iRuleNodeID );
        }
        else
        {
            /* Add the longest content for normal or mixed contents */
           pmdmax = FindLongestPattern( pmd );  
           if( pmdmax )
           {
               pmx = (PMX*)malloc(sizeof(PMX) );
               MEMASSERT(pmx,"pmx-content");
               pmx->RuleNode    = rnWalk;
               pmx->PatternMatchData= pmdmax;

               otnx->content_length = pmdmax->pattern_size;

               mpseAddPattern( mpse_obj, pmdmax->pattern_buf, pmdmax->pattern_size,
                 pmdmax->nocase,  /* NoCase: 1-NoCase, 0-Case */
                 pmdmax->offset, 
                 pmdmax->depth,
                 pmx,  
               rnWalk->iRuleNodeID );
           }
        }

        /* Add all of the OR contents 'file-list' content */     
        pmd = otn->ds_list[PLUGIN_PATTERN_MATCH_OR];
        while( pmd )
        {
            if(pmd->pattern_buf) 
            {
                pmx = (PMX*)malloc(sizeof(PMX) );
                MEMASSERT(pmx,"pmx-uricontent");
                pmx->RuleNode    = rnWalk;
                pmx->PatternMatchData= pmd;

                mpseAddPattern( mpse_obj, pmd->pattern_buf, pmd->pattern_size,
                pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
                pmd->offset,
                pmd->depth,
                pmx, //rnWalk,        /* rule ptr */ 
                //(unsigned)pmd,
                rnWalk->iRuleNodeID );
            }

            pmd = pmd->next;
        }

#ifdef DYNAMIC_PLUGIN
        /* 
        ** 
        ** Add in plugin contents for fast pattern matcher  
        **
        */     
        dd =(DynamicData*) otn->ds_list[PLUGIN_DYNAMIC];
        if( dd )
        {
            int n,i;
            n = dd->fastPatternContents(dd->contextData,FASTPATTERN_NORMAL,fplist,PLUGIN_MAX_FPLIST_SIZE);
            
            for(i=0;i<n;i++) 
            {
                pmd = (PatternMatchData*)malloc(sizeof(PatternMatchData) );
                MEMASSERT(pmd,"pmd-plugin-content");
                
                pmx = (PMX*)malloc(sizeof(PMX) );
                MEMASSERT(pmx,"pmx-plugin-content");
                
                pmx->RuleNode        = rnWalk;
                pmx->PatternMatchData= pmd;
                
                pmd->pattern_buf = fplist[i]->content;
                pmd->pattern_size= fplist[i]->length;
                pmd->nocase      = fplist[i]->noCaseFlag;
                pmd->offset      = 0;
                pmd->depth       = 0;
                
                mpseAddPattern( mpse_obj, 
                    pmd->pattern_buf, 
                    pmd->pattern_size,
                    pmd->nocase,  /* 1--NoCase, 0-Case */
                    pmd->offset,
                    pmd->depth,
                    pmx,  
                    rnWalk->iRuleNodeID );
            }
        }
#endif
    }
    /*
    **  We don't have PrepLongPatterns here, because we've found that
    **  the minimum length for the BM shift is not fulfilled by snort's
    **  ruleset.  We may add this in later, after initial performance
    **  has been verified.
    */
    
    mpsePrepPatterns( mpse_obj );
    if( fpDetect.debug ) mpsePrintInfo( mpse_obj );

}

/*
**
**  NAME
**    BuildMultiPatternGroups::
**
**  DESCRIPTION
**    This is the main function that sets up all the
**    port groups for a given PORT_RULE_MAP.  We iterate
**    through the dst and src ports building up port groups
**    where possible, and then build the generic set.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the port rule map to build
**
**  FORMAL OUTPUTS
**    None
**
*/
void BuildMultiPatternGroups( PORT_RULE_MAP * prm )
{
    int i;
    PORT_GROUP * pg;
     
    for(i=0;i<MAX_PORTS;i++)
    {
        
        pg = prmFindSrcRuleGroup( prm, i );
        if(pg)
        {
            if( fpDetect.debug )
                printf("---SrcRuleGroup-Port %d\n",i);
            BuildMultiPatGroup( pg );
            if( fpDetect.debug )
                printf("---SrcRuleGroup-UriPort %d\n",i);
            BuildMultiPatGroupsUri( pg );
        }

        pg = prmFindDstRuleGroup( prm, i );
        if(pg)
        {
            if( fpDetect.debug )
                printf("---DstRuleGroup-Port %d\n",i);
            BuildMultiPatGroup( pg );
            if( fpDetect.debug )
                printf("---DstRuleGroup-UriPort %d\n",i);
            BuildMultiPatGroupsUri( pg );
        }
    }

    pg = prm->prmGeneric;
     
    if( fpDetect.debug )
        printf("---GenericRuleGroup \n");
    BuildMultiPatGroup( pg );
    BuildMultiPatGroupsUri( pg );
}


/*
**
**  NAME
**    fpCreateFastPacketDetection::
**
**  DESCRIPTION
**    fpCreateFastPacketDetection initializes and creates the whole
**    FastPacket detection engine.  It reads the list of RTNs and OTNs
**    that snort creates on startup, and adds the RTN/OTN pair for a
**    rule to the appropriate PORT_GROUP.  The routine builds up
**    PORT_RULE_MAPs for TCP, UDP, ICMP, and IP.  More can easily be
**    added if necessary.
**
**    After initialization and setup, stats are printed out about the
**    different PORT_GROUPS.  
**
**  FORMAL INPUTS
**    None
**
**  FORMAL OUTPUTS
**    int - 0 is successful, other is failure.
**
*/
int fpCreateFastPacketDetection()
{
    RuleListNode *rule;
    RuleTreeNode *rtn;
    int sport;
    int dport;
    OptTreeNode * otn;
    int iBiDirectional = 0;

    OTNX * otnx;

    extern RuleListNode *RuleLists;

    prmTcpRTNX = prmNewMap();
    if(prmTcpRTNX == NULL)
        return 1;

    prmUdpRTNX = prmNewMap();
    if(prmUdpRTNX == NULL)
        return 1;

    prmIpRTNX = prmNewMap();
    if(prmIpRTNX == NULL)
        return 1;

    prmIcmpRTNX = prmNewMap();
    if(prmIcmpRTNX == NULL)
        return 1;

    for (rule=RuleLists; rule; rule=rule->next)
    {
        if(!rule->RuleList)
            continue;

        /*
        **  Process TCP signatures
        */
        if(rule->RuleList->TcpList)
        {
            for(rtn = rule->RuleList->TcpList; rtn != NULL; rtn = rtn->right)
            {
#ifdef LOCAL_DEBUG
                printf("** TCP\n");
                printf("** bidirectional = %s\n",
                        (rtn->flags & BIDIRECTIONAL) ? "YES" : "NO");
                printf("** not sp_flag = %d\n", rtn->not_sp_flag);
                printf("** not dp_flag = %d\n", rtn->not_dp_flag);
                printf("** hsp = %u\n", rtn->hsp);
                printf("** lsp = %u\n", rtn->lsp);
                printf("** hdp = %u\n", rtn->hdp);
                printf("** ldp = %u\n", rtn->ldp);
#endif

                /*
                **  Check for bi-directional rules
                */
                if(rtn->flags & BIDIRECTIONAL)
                {
                    iBiDirectional = 1;
                }else{
                    iBiDirectional = 0;
                }


                sport = CheckPorts(rtn->hsp, rtn->lsp);

                if( rtn->flags & ANY_SRC_PORT ) sport = -1;

                if( sport > 0 &&  rtn->not_sp_flag > 0 )
                {
                    sport = -1;
                }

                dport = CheckPorts(rtn->hdp, rtn->ldp);

                if( rtn->flags & ANY_DST_PORT ) dport = -1;

                if( dport > 0 && rtn->not_dp_flag > 0 )
                {
                    dport = -1;
                }

                /* Walk OTN list -Add as Content/UriContent, or NoContent */
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                    {
                        continue;
                    }

                    otnx = malloc( sizeof(OTNX) );
                    MEMASSERT(otnx,"otnx-TCP");

                    otnx->otn = otn;
                    otnx->rtn = rtn;
                    otnx->content_length = 0;

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("TCP Content-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRule(prmTcpRTNX, dport, sport, otnx);

                        if(iBiDirectional && (sport!=dport))
                        {
                            /*
                            **  We switch the ports.
                            */
                            prmAddRule(prmTcpRTNX, sport, dport, otnx);
                        }
                    }
                    if( OtnHasUriContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("TCP UriContent-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRuleUri(prmTcpRTNX, dport, sport, otnx);

                        if(iBiDirectional && (sport!=dport) )
                        {
                            /*
                            **  We switch the ports.
                            */
                            prmAddRuleUri(prmTcpRTNX, sport, dport, otnx);
                        }
                    }
                    if( !OtnHasContent( otn ) &&  !OtnHasUriContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("TCP NoContent-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmTcpRTNX, dport, sport, otnx);

                        if(iBiDirectional && (sport!=dport))
                        {
                            /*
                            **  We switch the ports.
                            */
                            prmAddRuleNC(prmTcpRTNX, sport, dport, otnx);
                        }
                    }
                }
            }
        }

        /*
        **  Process UDP signatures
        */
        if(rule->RuleList->UdpList)
        {
            for(rtn = rule->RuleList->UdpList; rtn != NULL; rtn = rtn->right)
            {
#ifdef LOCAL_DEBUG
                printf("** UDP\n");
                printf("** bidirectional = %s\n",
                        (rtn->flags & BIDIRECTIONAL) ? "YES" : "NO");
                printf("** not sp_flag = %d\n", rtn->not_sp_flag);
                printf("** not dp_flag = %d\n", rtn->not_dp_flag);
                printf("** hsp = %u\n", rtn->hsp);
                printf("** lsp = %u\n", rtn->lsp);
                printf("** hdp = %u\n", rtn->hdp);
                printf("** ldp = %u\n", rtn->ldp);
#endif

                /*
                **  Check for bi-directional rules
                */
                if(rtn->flags & BIDIRECTIONAL)
                {
                    iBiDirectional = 1;
                }else{
                    iBiDirectional = 0;
                }

                sport = CheckPorts(rtn->hsp, rtn->lsp);

                if( rtn->flags & ANY_SRC_PORT ) sport = -1;

                if(sport > 0 &&  rtn->not_sp_flag > 0 )
                {
                    sport = -1;
                }

                dport = CheckPorts(rtn->hdp, rtn->ldp);

                if( rtn->flags & ANY_DST_PORT ) dport = -1;


                if(dport > 0 && rtn->not_dp_flag > 0 )
                {
                    dport = -1;
                }

                /* Walk OTN list -Add as Content, or NoContent */
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                    {
                        continue;
                    }

                    otnx = malloc( sizeof(OTNX) );
                    MEMASSERT(otnx,"otnx-UDP");

                    otnx->otn = otn;
                    otnx->rtn = rtn;
                    otnx->content_length = 0;

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("UDP Content-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRule(prmUdpRTNX, dport, sport, otnx);

                        /*
                        **  If rule is bi-directional we switch
                        **  the ports.
                        */
                        if(iBiDirectional && (sport!=dport))
                        {
                            prmAddRule(prmUdpRTNX, sport, dport, otnx);
                        }
                    }
                    else
                    {
                        if(fpDetect.debug)
                        {
                            printf("UDP NoContent-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmUdpRTNX, dport, sport, otnx);

                        /*
                        **  If rule is bi-directional we switch
                        **  the ports.
                        */
                        if(iBiDirectional && (dport != sport) )
                        {
                            prmAddRuleNC(prmUdpRTNX, sport, dport, otnx);
                        }
                    }
                }
            }
        }

        /*
        **  Process ICMP signatures
        */
        if(rule->RuleList->IcmpList)
        {
            for(rtn = rule->RuleList->IcmpList; rtn != NULL; rtn = rtn->right)
            {
               /* Walk OTN list -Add as Content, or NoContent */
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    int type;
                    IcmpTypeCheckData * IcmpType;

                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                    {
                        continue;
                    }
                    otnx = malloc( sizeof(OTNX) );
                    MEMASSERT(otnx,"otnx-ICMP");

                    otnx->otn = otn;
                    otnx->rtn = rtn;
                    otnx->content_length = 0;

                    IcmpType = (IcmpTypeCheckData *)otn->ds_list[PLUGIN_ICMP_TYPE];
                    if( IcmpType && (IcmpType->operator == ICMP_TYPE_TEST_EQ) )
                    {
                        type = IcmpType->icmp_type;
                    }
                    else
                    {
                        type = -1;
                    }

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("ICMP Type=%d Content-Rule  %s\n",
                                    type,otn->sigInfo.message);
                        }
                        prmAddRule(prmIcmpRTNX, type, -1, otnx);
                    }
                    else
                    {
                        if(fpDetect.debug)
                        {
                            printf("ICMP Type=%d NoContent-Rule  %s\n",
                                    type,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmIcmpRTNX, type, -1, otnx);
                    }
                }
            }
        }

        /*
        **  Process IP signatures
        **
        **  NOTE:
        **  We may want to revisit this and add IP rules for TCP and
        **  UDP into the right port groups using the rule ports, instead
        **  of just using the generic port.
        */
        if(rule->RuleList->IpList)
        {
            for(rtn = rule->RuleList->IpList; rtn != NULL; rtn = rtn->right)
            {
                /* Walk OTN list -Add as Content, or NoContent */
                for( otn=rtn->down; otn; otn=otn->next )
                {
                    IpProtoData * IpProto;
                    int protocol;

                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                    {
                        continue;
                    }
                    otnx = malloc( sizeof(OTNX) );
                    MEMASSERT(otnx,"otnx-IP");

                    otnx->otn = otn;
                    otnx->rtn = rtn;
                    otnx->content_length = 0;

                    IpProto =  
                        (IpProtoData *)otn->ds_list[PLUGIN_IP_PROTO_CHECK] ;

                    if( IpProto )
                    {
                        protocol = IpProto->protocol;
                        if( IpProto->comparison_flag == GREATER_THAN )
                            protocol=-1; 
                        
                        if( IpProto->comparison_flag == LESS_THAN )
                            protocol=-1; 

                        if( IpProto->not_flag )
                            protocol=-1;
                    }
                    else
                    {
                        protocol = -1;
                    }

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("IP Proto=%d Content-Rule %s\n",
                                    protocol,otn->sigInfo.message);
                        }
                        prmAddRule(prmIpRTNX, protocol, -1, otnx);

                        if(protocol == IPPROTO_TCP || protocol == -1)
                        {
                            prmAddRule(prmTcpRTNX, -1, -1, otnx);
                        }
                        
                        if(protocol == IPPROTO_UDP || protocol == -1)
                        {
                            prmAddRule(prmUdpRTNX, -1, -1, otnx);
                        }

                        if(protocol == IPPROTO_ICMP || protocol == -1)
                        {
                            prmAddRule(prmIcmpRTNX, -1, -1, otnx);
                        }
                    }
                    else
                    {
                        if(fpDetect.debug)
                        {
                            printf("IP Proto=%d NoContent-Rule %s\n",
                                    protocol,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmIpRTNX, protocol, -1, otnx);

                        if(protocol == IPPROTO_TCP || protocol == -1)
                        {
                            prmAddRuleNC(prmTcpRTNX, -1, -1, otnx);
                        }
                        
                        if(protocol == IPPROTO_UDP || protocol == -1)
                        {
                            prmAddRuleNC(prmUdpRTNX, -1, -1, otnx);
                        }

                        if(protocol == IPPROTO_ICMP || protocol == -1)
                        {
                            prmAddRuleNC(prmIcmpRTNX, -1, -1, otnx);
                        }
                    }
                }
            }
        }
    }

    prmCompileGroups(prmTcpRTNX);
    prmCompileGroups(prmUdpRTNX);
    prmCompileGroups(prmIcmpRTNX);
    prmCompileGroups(prmIpRTNX);

    if(fpDetect.debug)printf("\n** TCP Rule Group Stats -- ");
    BuildMultiPatternGroups(prmTcpRTNX);
    if(fpDetect.debug)printf("\n** UDP Rule Group Stats -- ");
    BuildMultiPatternGroups(prmUdpRTNX);
    if(fpDetect.debug)printf("\n** Icmp Rule Group Stats -- ");
    BuildMultiPatternGroups(prmIcmpRTNX);
    if(fpDetect.debug)printf("\n** Ip Rule Group Stats -- ");
    BuildMultiPatternGroups(prmIpRTNX) ;

    if(fpDetect.debug)
    {
        printf("\n** TCP Rule Group Stats -- ");
        prmShowStats(prmTcpRTNX);
    
        printf("\n** UDP Rule Group Stats -- ");
        prmShowStats(prmUdpRTNX);
    
        printf("\n** ICMP Rule Group Stats -- ");
        prmShowStats(prmIcmpRTNX);
    
        printf("\n** IP Rule Group Stats -- ");
        prmShowStats(prmIpRTNX);
    }

    return 0;
}

/*
**  Wrapper for prmShowEventStats
*/
int fpShowEventStats()
{
    /*
    **  If not debug, then we don't print anything.
    */
    if(!fpDetect.debug)
    {
        return 1;
    }

    printf("\n** TCP Event Stats -- ");  prmShowEventStats(prmTcpRTNX);
    printf("\n** UDP Event Stats -- ");  prmShowEventStats(prmUdpRTNX);
    printf("\n** ICMP Event Stats -- "); prmShowEventStats(prmIcmpRTNX);
    printf("\n** IP Event Stats -- ");    prmShowEventStats(prmIpRTNX);
    return 0;
}

