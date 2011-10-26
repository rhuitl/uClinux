/* $Id$ */
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

/*  I N C L U D E S  ************************************************/
#ifndef __DETECT_H__
#define __DETECT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//#include "snort.h"
#include "decode.h"
#include "rules.h"
#include "parser.h"
#include "log.h"
#include "event.h"
/*  P R O T O T Y P E S  ******************************************************/
extern int do_detect;
extern int do_detect_content;

/* rule match action functions */
int PassAction();
int ActivateAction(Packet *, OptTreeNode *, Event *);
int AlertAction(Packet *, OptTreeNode *, Event *);
int DropAction(Packet *, OptTreeNode *, Event *);
#ifdef GIDS
int SDropAction(Packet *, OptTreeNode *, Event *);
int RejectAction(Packet *, OptTreeNode *, Event *);
#endif /* GIDS */
int DynamicAction(Packet *, OptTreeNode *, Event *);
int LogAction(Packet *, OptTreeNode *, Event *);

/* detection/manipulation funcs */
int Preprocess(Packet *);
int  Detect(Packet *);
void CallOutputPlugins(Packet *);
int EvalPacket(ListHead *, int, Packet * );
int EvalHeader(RuleTreeNode *, Packet *, int);
int EvalOpts(OptTreeNode *, Packet *);
void TriggerResponses(Packet *, OptTreeNode *);
int CheckAddrPort(IpAddrSet *, u_short, u_short, Packet *, u_int32_t, int);

#include "bitop_funcs.h"
static inline void DisableDetect(Packet *p)
{
    boResetBITOP(p->preprocessor_bits);
    do_detect_content = 0;
}

static inline void DisableAllDetect(Packet *p)
{
    boResetBITOP(p->preprocessor_bits);
    do_detect = do_detect_content = 0;
}

/* detection modules */
int CheckBidirectional(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcIP(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstIP(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcIPNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstIPNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcPortEqual(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstPortEqual(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcPortNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstPortNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *);

int RuleListEnd(Packet *, struct _RuleTreeNode *, RuleFpList *);
int OptListEnd(Packet *, struct _OptTreeNode *, OptFpList *);
void CallLogPlugins(Packet *, char *, void *, Event *);
void CallAlertPlugins(Packet *, char *, void *, Event *);
void CallLogFuncs(Packet *, char *, ListHead *, Event *);
void CallAlertFuncs(Packet *, char *, ListHead *, Event *);

void ObfuscatePacket(Packet *p);

#endif /* __DETECT_H__ */
