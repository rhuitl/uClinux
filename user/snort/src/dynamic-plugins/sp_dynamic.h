/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005 Sourcefire Inc.
 *
 * Author: Steven Sturges
 *
 */

/* $Id$ */

#ifndef __SP_DYNAMIC_H_
#define __SP_DYNAMIC_H_

#include "sf_dynamic_engine.h"

typedef struct _DynamicData
{
    void *contextData;
    OTNCheckFunction checkFunction;
    OTNHasFlowFunction hasFlowFunction;
    OTNHasFlowFunction hasFlowbitFunction;
    int fpContentFlags;
    GetFPContentFunction fastPatternContents;
} DynamicData;

void SetupDynamic(void);
int RegisterDynamicRule(u_int32_t gid, u_int32_t sid, void *info,
                        OTNCheckFunction chkFunc, OTNHasFlowFunction hasFlowFunc,
                        OTNHasFlowFunction hasFlowbitFunc,
                        int fpContentFlags, GetFPContentFunction fpFunc);

u_int32_t DynamicFlowbitRegister(char *name, int op);
int DynamicFlowbitCheck(void *pkt, int op, u_int32_t id);
int DynamicAsn1Detect(void *pkt, void *ctxt, u_int8_t *cursor);
int DynamicHasFlow(OptTreeNode *otn);
int DynamicHasFlowbit(OptTreeNode *otn);

#endif  /* __SP_DYNAMIC_H_ */

