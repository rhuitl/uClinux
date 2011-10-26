/*
** $Id$
**
** perf.h
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker <droelker@sourcefire.com>
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
**
**
**  DESCRIPTION
**    These are the basic functions and structures that are needed to call 
**    performance functions.
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker
**
**
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
**
*/

#ifndef _PERF_H
#define _PERF_H

#define SFPERF_BASE         0x0001
#define SFPERF_FLOW         0x0002
#define SFPERF_EVENT        0x0004
#define SFPERF_BASE_MAX     0x0008
#define SFPERF_CONSOLE      0x0010
#define SFPERF_FILE         0x0020
#define SFPERF_PKTCNT       0x0040
#define SFPERF_SUMMARY      0x0080
#define SFPERF_FILECLOSE    0x0100

#ifndef UINT64
#define UINT64 unsigned long long
#endif

#include "perf-base.h"
#include "perf-flow.h"
#include "perf-event.h"

typedef struct _SFPERF {

    int    iPerfFlags;
    unsigned int    iPktCnt;

    int    sample_interval;
    int    sample_time;

    SFBASE  sfBase;
    SFFLOW  sfFlow;
    SFEVENT sfEvent;

    char    file[1024];
    FILE  * fh;
    
} SFPERF;

int sfInitPerformanceStatistics(SFPERF *sfPerf);
int sfSetPerformanceSampleTime(SFPERF *sfPerf, int iSeconds);
int sfSetPerformanceAccounting(SFPERF *sfPerf, int iReset);
int sfSetPerformanceStatistics(SFPERF *sfPerf, int iFlag);
int sfSetPerformanceStatisticsEx(SFPERF *sfPerf, int iFlag, void * param);
int sfRotatePerformanceStatisticsFile(SFPERF *sfPerf);
int sfPerformanceStats(SFPERF *sfPerf, unsigned char *pucPacket, int len,
                       int iRebuiltPkt);
int sfProcessPerfStats(SFPERF *sfPerf);
int CheckSampleInterval(time_t curr_time, SFPERF *sfPerf);

#endif
