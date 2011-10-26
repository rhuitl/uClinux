/*
**  $Id$
** 
**  profiler.c
**
**  Copyright (C) 2005 Sourcefire,Inc
**  Steven Sturges <ssturges@sourcefire.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snort.h"
#include "rules.h"
#include "parser.h"
#include "plugin_enum.h"
#include "util.h"
#include "rules.h"
#include "profiler.h"
#include <unistd.h>

#ifdef PERF_PROFILING
double ticks_per_microsec = 0.0;

void getTicksPerMicrosec()
{
    if (ticks_per_microsec == 0.0)
    {
        PROFILE_VARS;

        PROFILE_START;
#ifndef WIN32
        sleep(1);
#else
        Sleep(1000);
#endif
        PROFILE_END;
        ticks_per_microsec = (double) ticks_delta/1000000;
    }
}

typedef struct _OTN_WorstPerformer
{
    OptTreeNode *otn;
    struct _OTN_WorstPerformer *next;
    struct _OTN_WorstPerformer *prev;
    double ticks_per_check;
    double ticks_per_match;
    double ticks_per_nomatch;
} OTN_WorstPerformer;

OTN_WorstPerformer *worstPerformers = NULL;
void PrintWorstRules(int numToPrint)
{
    OptTreeNode *otn;
    OTN_WorstPerformer *node, *tmp;
    int num = 0;

    getTicksPerMicrosec();

    if (numToPrint != -1)
    {
        LogMessage("Rule Profile Statistics (worst %d rules)\n", numToPrint);
    }
    else
    {
        LogMessage("Rule Profile Statistics (all rules)\n");
    }
    LogMessage("==========================================================\n");

    if (!worstPerformers)
    {
        LogMessage("No rules were profiled\n");
        return;
    }

    LogMessage("%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
             6, "Num",
             9, "SID", 4, "GID",
            11, "Checks",
            10, "Matches",
            10, "Alerts",
            20, "Microsecs",
            11, "Avg/Check",
            11, "Avg/Match",
            13, "Avg/Nonmatch");
    LogMessage("%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
            6, "===",
            9, "===", 4, "===",
            11, "======",
            10, "=======",
            10, "======",
            20, "=====",
            11, "=========",
            11, "=========",
            13, "============");

    for (node = worstPerformers, num=1;
         node && ((numToPrint < 0) ? 1 : (num <= numToPrint));
         node= node->next, num++)
    {
        //if (!node)
        //    break;
        otn = node->otn;
#ifdef WIN32
        LogMessage("%*d%*d%*d%*d%*d%*d%*I64i%*.1f%*.1f%*.1f\n",
#else
        LogMessage("%*d%*d%*d%*d%*d%*d%*llu%*.1f%*.1f%*.1f\n",
#endif
            6, num, 9, otn->sigInfo.id, 4, otn->sigInfo.generator,
            11, otn->checks, 
            10, otn->matches,
            10, otn->alerts,
            20, (UINT64)(otn->ticks/ticks_per_microsec),
            11, node->ticks_per_check/ticks_per_microsec,
            11, node->ticks_per_match/ticks_per_microsec,
            13, node->ticks_per_nomatch/ticks_per_microsec);
    }

    /* Do some cleanup */
    for (node = worstPerformers; node; )
    {
        tmp = node->next;
        free(node);
        node = tmp;
    }
}

void CollectRTNProfile(RuleTreeNode *list)
{
    RuleTreeNode *rtn;
    OptTreeNode *otn;
    OTN_WorstPerformer *new, *node, *last = NULL;
    char got_position;

    for (rtn = list; rtn; rtn = rtn->right)
    {
        for (otn = rtn->down; otn; otn = otn->next)
        {
            /* Only log info if OTN has actually been eval'd */
            if (otn->checks > 0 && otn->ticks > 0)
            {
                double ticks_per_check = (double)otn->ticks/otn->checks;
                double ticks_per_nomatch;
                double ticks_per_match;

                if (otn->matches)
                    ticks_per_match = (double)otn->ticks_match/otn->matches;
                else
                    ticks_per_match = 0.0;

                if (otn->checks == otn->matches)
                    ticks_per_nomatch = 0.0;
                else
                    ticks_per_nomatch = (double)(otn->ticks - otn->ticks_match)/
                                         (otn->checks - otn->matches);
                
                /* Find where he goes in the list
                 * Cycle through the list and add
                 * this where it goes
                 */
                new = (OTN_WorstPerformer *)calloc(1, sizeof(OTN_WorstPerformer));
                new->otn = otn;
                new->ticks_per_check = ticks_per_check;
                new->ticks_per_match = ticks_per_match;
                new->ticks_per_nomatch = ticks_per_nomatch;

                got_position = 0;

                for (node = worstPerformers; node && !got_position; node = node->next)
                {
                    last = node;
                    switch (pv.profile_rules_sort)
                    {
                        case PROFILE_SORT_CHECKS:
                            if (otn->checks >= node->otn->checks)
                            {
                                got_position = 1;
                            }
                            break;
                        case PROFILE_SORT_MATCHES:
                            if (otn->matches >= node->otn->matches)
                            {
                                got_position = 1;
                            }
                            break;
                        case PROFILE_SORT_NOMATCHES:
                            if (otn->checks - otn->matches >
                                    node->otn->checks - node->otn->matches)
                            {
                                got_position = 1;
                            }
                            break;
                        case PROFILE_SORT_AVG_TICKS_PER_MATCH:
                            if (ticks_per_match >= node->ticks_per_match)
                            {
                                got_position = 1;
                            }
                            break;
                        case PROFILE_SORT_AVG_TICKS_PER_NOMATCH:
                            if (ticks_per_nomatch >= node->ticks_per_nomatch)
                            {
                                got_position = 1;
                            }
                            break;
                        case PROFILE_SORT_TOTAL_TICKS:
                            if (otn->ticks >= node->otn->ticks)
                            {
                                got_position = 1;
                            }
                            break;
                        default:
                        case PROFILE_SORT_AVG_TICKS:
                            if (ticks_per_check >= node->ticks_per_check)
                            {
                                got_position = 1;
                            }
                            break;
                    }
                    if (got_position)
                        break;
                }

                if (node)
                {
                    new->next = node;
                    new->prev = node->prev;
                    node->prev = new;
                    if (new->prev)
                        new->prev->next = new;
                    /* Reset the head of list */
                    if (node == worstPerformers)
                        worstPerformers = new;
                }
                else
                {
                    if (!last)
                    {
                        worstPerformers = new;
                    }
                    else
                    {
                        new->prev = last;
                        last->next = new;
                    }
                }
            }
        }
    }
}

extern RuleListNode *RuleLists;

void ShowRuleProfiles()
{
    /* Cycle through all Rules, print ticks & check count for each */
    RuleListNode *rule;

    if (!pv.profile_rules_flag)
        return;

    for (rule=RuleLists; rule; rule=rule->next)
    {
        if (!rule->RuleList)
            continue;

        /* TCP list */
        CollectRTNProfile(rule->RuleList->TcpList);

        /* UDP list */
        CollectRTNProfile(rule->RuleList->UdpList);

        /* ICMP list */
        CollectRTNProfile(rule->RuleList->IcmpList);

        /* IP list */
        CollectRTNProfile(rule->RuleList->IpList);
    }

    /* Specifically call out a top xxx or something? */
    PrintWorstRules(pv.profile_rules_flag);
    return;
}

/* The global total for snort */
PreprocStats totalPerfStats;

PreprocStatsNode *PreprocStatsNodeList;

int max_layers = 0;

void RegisterPreprocessorProfile(char *keyword, PreprocStats *stats, int layer, PreprocStats *parent)
{
    PreprocStatsNode *node;

    if (!stats)
        return;

    node = PreprocStatsNodeList;

    if (node == NULL)
    {
        /* alloc the node */
        PreprocStatsNodeList = (PreprocStatsNode *)SnortAlloc(sizeof(PreprocStatsNode));

        PreprocStatsNodeList->name = (char *)SnortAlloc((strlen(keyword) + 1) * sizeof(char));

        /* copy the keyword */
        SnortStrncpy(PreprocStatsNodeList->name, keyword, strlen(keyword) +1);

        /* Set the stats reference */
        PreprocStatsNodeList->stats = stats;
        PreprocStatsNodeList->parent = parent;
        PreprocStatsNodeList->layer = layer;
    }
    else
    {
        while (node->next != NULL)
        {
            if (!strcasecmp(node->name, keyword))
            {
                FatalError("Duplicate Preprocessor Stats Name\n");
            }
            node = node->next;
        }

        node->next = (PreprocStatsNode *)SnortAlloc(sizeof(PreprocStatsNode));

        node = node->next;

        node->name = (char *)SnortAlloc((strlen(keyword) + 1) * sizeof(char));

        /* copy the keyword */
        SnortStrncpy(node->name, keyword, strlen(keyword) +1);

        /* Set the stats reference */
        node->stats = stats;
        node->parent = parent;
        node->layer = layer;
    }

    if (layer > max_layers)
        max_layers = layer;
}

typedef struct _Preproc_WorstPerformer
{
    PreprocStatsNode *node;
    struct _Preproc_WorstPerformer *next;
    struct _Preproc_WorstPerformer *prev;
    struct _Preproc_WorstPerformer *children;
    double ticks_per_check;
    double pct_of_parent;
} Preproc_WorstPerformer;

Preproc_WorstPerformer *worstPreprocPerformers = NULL;
void FreePreprocPerformance(Preproc_WorstPerformer *idx)
{
    Preproc_WorstPerformer *child, *tmp;
    child = idx->children;
    while (child)
    {
        FreePreprocPerformance(child);
        tmp = child;
        child = child->next;
        free(tmp);
    }
}

void PrintPreprocPerformance(int num, Preproc_WorstPerformer *idx)
{
    Preproc_WorstPerformer *child;
    int i;
    /* indent 'Num' based on the layer */
    unsigned int indent = 6 - (5 - idx->node->layer);

    if (num != 0)
    {
        indent += 2;
#ifdef WIN32
        LogMessage("%*d%*s%*d%*d%*d%*I64i%*.1f%*.1f\n",
#else
        LogMessage("%*d%*s%*d%*d%*d%*llu%*.1f%*.1f\n",
#endif
            indent, num,
            28 - indent, idx->node->name, 6, idx->node->layer,
            11, idx->node->stats->checks, 
            11, idx->node->stats->exits, 
            20, (UINT64)(idx->node->stats->ticks/ticks_per_microsec),
            11, idx->ticks_per_check/ticks_per_microsec,
            14, idx->pct_of_parent);
    }
    else
    {
        /* The totals */
        indent += strlen(idx->node->name);
#ifdef WIN32
        LogMessage("%*s%*s%*d%*d%*d%*I64i%*.1f%*.1f\n",
#else
        LogMessage("%*s%*s%*d%*d%*d%*llu%*.1f%*.1f\n",
#endif
            indent, idx->node->name,
            28 - indent, idx->node->name, 6, idx->node->layer,
            11, idx->node->stats->checks, 
            11, idx->node->stats->exits, 
            20, (UINT64)(idx->node->stats->ticks/ticks_per_microsec),
            11, idx->ticks_per_check/ticks_per_microsec,
            14, idx->pct_of_parent);
    }

    child = idx->children;

    i = 1;
    while (child)
    {
        PrintPreprocPerformance(i++, child);
        child = child->next;
    }
}

void PrintWorstPreprocs(int numToPrint)
{
    Preproc_WorstPerformer *idx, *tmp;
    Preproc_WorstPerformer *total = NULL;
    int num = 0;

    getTicksPerMicrosec();

    if (numToPrint != -1)
    {
        LogMessage("Preprocessor Profile Statistics (worst %d)\n", numToPrint);
    }
    else
    {
        LogMessage("Preprocessor Profile Statistics (all)\n");
    }
    LogMessage("==========================================================\n");
    if (!worstPreprocPerformers)
    {
        LogMessage("No Preprocessors were profiled\n");
        return;
    }

    LogMessage("%*s%*s%*s%*s%*s%*s%*s%*s\n",
            4, "Num",
            24, "Preprocessor",
            6, "Layer",
            11, "Checks",
            11, "Exits",
            20, "Microsecs",
            11, "Avg/Check",
            14, "Pct of Caller");
    LogMessage("%*s%*s%*s%*s%*s%*s%*s%*s\n",
            4, "===",
            24, "============",
            6, "=====",
            11, "======",
            11, "=====",
            20, "=====",
            11, "=========",
            14, "=============");

    for (idx = worstPreprocPerformers, num=1;
         idx && ((numToPrint < 0) ? 1 : (num <= numToPrint));
         idx= idx->next, num++)
    {
        /* Skip the total counter */
        if (idx->node->stats == &totalPerfStats)
        {
            num--;
            total = idx;
            continue;
        }
        //if (!idx)
        //    break;
        PrintPreprocPerformance(num, idx);
        //LogMessage("%*d%*s%*d%*d%*llu%*.1f%*.1f\n",
        //    6, num, 20, idx->node->name, 6, idx->node->layer,
        //    11, idx->node->stats->checks, 
        //    11, idx->node->stats->exits, 
        //    20, idx->node->stats->ticks,
        //    11, idx->ticks_per_check,
        //    14, idx->pct_of_parent);
    }
    if (total)
        PrintPreprocPerformance(0, total);

    /* Do some cleanup */
    for (idx = worstPreprocPerformers; idx; )
    {
        tmp = idx->next;
        free(idx);
        idx = tmp;
    }
}

Preproc_WorstPerformer *findPerfParent(PreprocStatsNode *node,
                                       Preproc_WorstPerformer *top)
{
    Preproc_WorstPerformer *list = top;
    Preproc_WorstPerformer *parent;

    if (!list)
        return NULL;

    if (list->node->layer > node->layer)
        return NULL;

    while (list)
    {
        if (list->node->stats == node->parent)
        {
            parent = list;
            return parent;
        }

        parent = findPerfParent(node, list->children);

        if (parent)
            return parent;

        list = list->next;
    }

    return NULL;
}

extern PreprocStats mpsePerfStats, rulePerfStats;
void ShowPreprocProfiles()
{
    /* Cycle through all Rules, print ticks & check count for each */
    PreprocStatsNode *idx;
    int layer;
    Preproc_WorstPerformer *parent, *new, *this = NULL, *last = NULL;
    char got_position;
    Preproc_WorstPerformer *listhead;
    double ticks_per_check;

    if (!pv.profile_preprocs_flag)
        return;

    /* Adjust mpse stats to not include rule evaluation */
    mpsePerfStats.ticks -= rulePerfStats.ticks;

    for (layer=0;layer<=max_layers;layer++)
    {

        for (idx = PreprocStatsNodeList; idx; idx = idx->next)
        {
            if (idx->stats->checks == 0 || idx->stats->ticks == 0)
                continue;

            if (idx->layer != layer)
                continue;

            last = NULL;

            ticks_per_check = (double)idx->stats->ticks/idx->stats->checks;

            new = SnortAlloc(sizeof(Preproc_WorstPerformer));
            new->node = idx;
            new->ticks_per_check = ticks_per_check;

            if (idx->parent)
            {
                /* Find this idx's parent in the list */
                parent = findPerfParent(idx, worstPreprocPerformers);
                if (parent && (parent->node->stats != &totalPerfStats))
                {
                    listhead = parent->children;
                }
                else
                {
                    listhead = worstPreprocPerformers;
                    parent = NULL;
                }
                new->pct_of_parent = (double)idx->stats->ticks/idx->parent->ticks*100.0;
            }
            else
            {
                parent = NULL;
                new->pct_of_parent = 0.0;
                listhead = worstPreprocPerformers;
            }

            got_position = 0;

            for (this = listhead; this && !got_position; this = this->next)
            {
                last = this;
                switch (pv.profile_preprocs_sort)
                {
                    case PROFILE_SORT_CHECKS:
                        if (new->node->stats->checks >= this->node->stats->checks)
                        {
                            got_position = 1;
                        }
                        break;
                    case PROFILE_SORT_TOTAL_TICKS:
                        if (new->node->stats->ticks >= this->node->stats->ticks)
                        {
                            got_position = 1;
                        }
                        break;
                    default:
                    case PROFILE_SORT_AVG_TICKS:
                        if (new->ticks_per_check >= this->ticks_per_check)
                        {
                            got_position = 1;
                        }
                        break;
                }
                if (got_position)
                    break;
            }
            if (this)
            {
                new->next = this;
                new->prev = this->prev;
                this->prev = new;
                if (new->prev)
                    new->prev->next = new;
                /* Reset the head of the list */
                if (this == listhead)
                {
                    if (parent)
                    {
                        parent->children = new;
                    }
                    else
                    {
                        worstPreprocPerformers = new;
                    }
                }
            }
            else
            {
                if (!last)
                {
                    if (parent)
                    {
                        parent->children = new;
                    }
                    else
                    {
                        worstPreprocPerformers = new;
                    }
                }
                else
                {
                    new->prev = last;
                    last->next = new;
                }
            }
        }
    }

    PrintWorstPreprocs(pv.profile_preprocs_flag);
}

#endif
