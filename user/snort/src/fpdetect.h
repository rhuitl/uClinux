/*
** $Id$
**
** fpfuncs.h
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker <droelker@sourcefire.com>
** Marc Norton <mnorton@sourcefire.com>
**
** NOTES
** 5.15.02 - Initial Source Code. Norton/Roelker
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

#ifndef __FPDETECT_H__
#define __FPDETECT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fpcreate.h"

#ifndef DEBUG
    #ifndef INLINE
        #define INLINE inline
    #endif
#else
    #ifdef INLINE
        #undef INLINE
    #endif
    #define INLINE   
#endif /* DEBUG */

int OtnXMatchDataInitialize();

/*
**  Function for fpcreate to use to pass detection options to
**  fpdetect.
*/
int fpSetDetectionOptions(FPDETECT *fpDetect);

/*
**  This is the only function that is needed to do an
**  inspection on a packet.
*/
int fpEvalPacket(Packet *p);

int fpLogEvent(RuleTreeNode *rtn, OptTreeNode *otn, Packet *p);

#endif
