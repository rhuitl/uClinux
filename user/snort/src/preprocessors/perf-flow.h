/* $Id$ */
/*
** perf-flow.h
**
** Copyright (C) 2002 Sourcefire,Inc
** Marc Norton <mnorton@sourcefire.com>
** Dan Roelker <droelker@sourcefire.com>
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


#ifndef _PERF_FLOW_H
#define _PERF_FLOW_H

#define SF_MAX_PKT_LEN 4500
#define SF_MAX_PORT (64*1024)

typedef struct _portflow {

    double   totperc[SF_MAX_PORT];
    double   sport_rate[SF_MAX_PORT];
    double   dport_rate[SF_MAX_PORT];

} PORTFLOW;

typedef struct _icmpflow {

    double totperc[256];
    int    display[256];

} ICMPFLOW;

typedef struct _sfflow {

    UINT64   *pktLenCnt;
    UINT64    pktTotal;

    UINT64   byteTotal;

    UINT64   *pktLenPercent;
    
    UINT64   *portTcpSrc;
    UINT64   *portTcpDst;
    UINT64   *portUdpSrc;
    UINT64   *portUdpDst;

    UINT64   *typeIcmp;

    UINT64    portTcpHigh;
    UINT64    portTcpTotal;

    UINT64    portUdpHigh;
    UINT64    portUdpTotal;

    UINT64    typeIcmpTotal;

    int       maxPortToTrack;
}  SFFLOW;

typedef struct _sfflow_stats {

    double    pktLenPercent[SF_MAX_PKT_LEN];
   
    double    trafficTCP;
    double    trafficUDP;
    double    trafficICMP;
    double    trafficOTHER;

    PORTFLOW  portflowTCP;
    double    portflowHighTCP;

    PORTFLOW  portflowUDP;
    double    portflowHighUDP;

    ICMPFLOW  flowICMP;


}  SFFLOW_STATS;

/*
**  Functions for the performance functions to call
*/
int InitFlowStats   (SFFLOW *sfFlow);
int UpdateFlowStats (SFFLOW *sfFlow, unsigned char *pucBuffer, int len,
        int iRebuiltPkt);
int ProcessFlowStats(SFFLOW *sfFlow);

/*
**  These functions wrap the perf-flow functionality within
**  decode.c so we don't have to decode the packet for our
**  own stats.  Helps speed.
*/
int UpdateUDPFlowStatsEx(int sport, int dport, int len );
int UpdateTCPFlowStatsEx(int sport, int dport, int len );
int UpdateICMPFlowStatsEx(int type, int len);

#endif


