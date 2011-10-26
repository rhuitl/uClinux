/*
**  $Id$
**
**  fpclass.h
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker <droelker@sourcefire.com>
** Marc Norton <mnorton@sourcefire.com>
**
** NOTES
** 5.7.02 - Initial Sourcecode.  Norton/Roelker
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
** 6/13/05 - marc norton
**   Added plugin support for fast pattern match data, requires DYNAMIC_PLUGIN be defined
**
*/
#ifndef __FPCREATE_H__
#define __FPCREATE_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rules.h"
#include "parser.h"
#include "pcrm.h"

#ifndef INLINE
#define INLINE inline
#endif

/*
 *  This controls how many fast pattern match contents may be 
 *  used/retrieved per rule in fpcreate.c.
 */
#define PLUGIN_MAX_FPLIST_SIZE 16

/*
**  This structure holds the RTN and OTN
**  for a specific rule.  This way we can
**  verify each rule and stay within the
**  current snort rule architecture.
*/
typedef struct _otnx_{

   OptTreeNode   * otn;
   RuleTreeNode  * rtn; 
   unsigned int    content_length;

} OTNX;

typedef struct _pmx_ {

   void * RuleNode;
   void * PatternMatchData;

} PMX;

/*
**  This structure holds configuration options for the 
**  detection engine.
*/
typedef struct _FPDETECT {
    
    int inspect_stream_insert;
    int search_method;
    int search_method_verbose;
    int debug;
    int max_queue_events;

} FPDETECT;

/*
**  This function initializes the detection engine configuration
**  options before setting them.
*/
int fpInitDetectionEngine();

/*
**  This is the main routine to create a FastPacket inspection
**  engine.  It reads in the snort list of RTNs and OTNs and
**  assigns them to PORT_MAPS.
*/
int fpCreateFastPacketDetection();

/*
**  Functions that allow the detection routins to 
**  find the right classification for a given packet.
*/
int prmFindRuleGroupTcp(int dport, int sport, PORT_GROUP ** src, PORT_GROUP **dst , PORT_GROUP ** gen);
int prmFindRuleGroupUdp(int dport, int sport, PORT_GROUP ** src, PORT_GROUP **dst , PORT_GROUP ** gen);
int prmFindRuleGroupIp(int ip_proto, PORT_GROUP **ip_group, PORT_GROUP ** gen);
int prmFindRuleGroupIcmp(int type, PORT_GROUP **type_group, PORT_GROUP ** gen);

int fpSetDetectSearchMethod( char * method );
int fpSetDebugMode();
int fpSetStreamInsert();
int fpSetMaxQueueEvents(int iNum);

/*
**  Shows the event stats for the created FastPacketDetection
*/
int fpShowEventStats();

#endif
