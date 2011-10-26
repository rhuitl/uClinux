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

#ifndef __SP_PREPROCOPT_H_
#define __SP_PREPROCOPT_H_

#include "sf_dynamic_engine.h"

void PreprocessorRuleOptionsInit();
int RegisterPreprocessorRuleOption(char *optionName,
                                   PreprocOptionInit initFunc,
                                   PreprocOptionEval evalFunc,
                                   PreprocOptionCleanup cleanupFunc);
int GetPreprocessorRuleOptionFuncs(char *optionName,
                                   void **initFunc,
                                   void **evalFunc);

#endif  /* __SP_PREPROCOPT_H_ */

