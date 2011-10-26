/*
** Copyright (C) 2005 Sourcefire, Inc.
** Author: Steven Sturges <ssturges@sourcefire.com>
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

#ifndef __PROFILER_H__
#define __PROFILER_H__

#ifdef PERF_PROFILING
#ifndef UINT64
#define UINT64 unsigned long long
#endif

/* Assembly to find clock ticks.  Intel only */
#ifdef WIN32
#define rdtsc(val) \
    QueryPerformanceCounter((PLARGE_INTEGER)&val)
#else
#if (defined(__i386) || defined(__ia64) || defined(__amd64) )
#define rdtsc(val) \
    __asm__ __volatile__ ("rdtsc" : "=A" (val))
#else
#define rdtsc(val)
#endif
#endif

/* Sort preferences for rule profiling */
#define PROFILE_SORT_CHECKS 1
#define PROFILE_SORT_MATCHES 2
#define PROFILE_SORT_NOMATCHES 3
#define PROFILE_SORT_AVG_TICKS 4
#define PROFILE_SORT_AVG_TICKS_PER_MATCH 5
#define PROFILE_SORT_AVG_TICKS_PER_NOMATCH 6
#define PROFILE_SORT_TOTAL_TICKS 7

/* MACROS that handle profiling of rules and preprocessors */
#define PROFILE_VARS UINT64 ticks_start = 0, ticks_end = 0, ticks_delta

#define PROFILE_START \
    rdtsc(ticks_start);

#define PROFILE_END \
    rdtsc(ticks_end); \
    ticks_delta = ticks_end - ticks_start;

#ifndef PROFILING_RULES
#define PROFILING_RULES pv.profile_rules_flag
#endif

#define OTN_PROFILE_START(otn) \
    if (PROFILING_RULES) { \
        otn->checks++; \
        PROFILE_START; \
    }

#define OTN_PROFILE_END_MATCH(otn) \
    if (PROFILING_RULES) { \
        PROFILE_END; \
        otn->ticks += ticks_delta; \
        otn->ticks_match += ticks_delta; \
        otn->matches++; \
    }

#define OTN_PROFILE_NOALERT(otn) \
    if (PROFILING_RULES) { \
        otn->noalerts=1; \
    }

#define OTN_PROFILE_END_NOMATCH(otn) \
    if (PROFILING_RULES) { \
        PROFILE_END; \
        otn->ticks += ticks_delta; \
        otn->ticks_no_match += ticks_delta; \
    }
#define OTN_PROFILE_ALERT(otn) otn->alerts++;

#ifndef PROFILING_PREPROCS
#define PROFILING_PREPROCS pv.profile_preprocs_flag
#endif

#define PREPROC_PROFILE_START(ppstat) \
    if (PROFILING_PREPROCS) { \
        ppstat.checks++; \
        PROFILE_START; \
        ppstat.ticks_start = ticks_start; \
    } 

#define PREPROC_PROFILE_REENTER_START(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_START; \
        ppstat.ticks_start = ticks_start; \
    } 

#define PREPROC_PROFILE_TMPSTART(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_START; \
    } 

#define PREPROC_PROFILE_END(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_END; \
        ppstat.exits++; \
        ppstat.ticks += ticks_end - ppstat.ticks_start; \
    } 

#define PREPROC_PROFILE_REENTER_END(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_END; \
        ppstat.ticks += ticks_end - ppstat.ticks_start; \
    } 

#define PREPROC_PROFILE_TMPEND(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_END; \
        ppstat.ticks += ticks_end - ppstat.ticks_start; \
    } 

/************** Profiling API ******************/
void ShowRuleProfiles();

/* Preprocessor stats info */
typedef struct _PreprocStats
{
    UINT64 ticks, ticks_start;
    unsigned int checks;
    unsigned int exits;
} PreprocStats;

typedef struct _PreprocStatsNode
{
    PreprocStats *stats;
    char *name;
    int layer;
    PreprocStats *parent;
    struct _PreprocStatsNode *next;
} PreprocStatsNode;

void RegisterPreprocessorProfile(char *keyword, PreprocStats *stats, int layer, PreprocStats *parent);
void ShowPreprocProfiles();
extern PreprocStats totalPerfStats;
#else
#define PROFILE_VARS
#define OTN_PROFILE_START(otn)
#define OTN_PROFILE_END_MATCH(otn)
#define OTN_PROFILE_END_NOMATCH(otn)
#define OTN_PROFILE_NOALERT(otn)
#define OTN_PROFILE_ALERT(otn)
#define PREPROC_PROFILE_START(ppstat)
#define PREPROC_PROFILE_REENTER_START(ppstat)
#define PREPROC_PROFILE_TMPSTART(ppstat)
#define PREPROC_PROFILE_END(ppstat)
#define PREPROC_PROFILE_REENTER_END(ppstat)
#define PREPROC_PROFILE_TMPEND(ppstat)
#endif

#endif  /* __PROFILER_H__ */
