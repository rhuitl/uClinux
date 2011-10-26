/* $Id$ */
/*
 * sp_preprocopt.c
 *
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
 * Purpose:
 *      Supports preprocessor defined rule options.
 *
 * Arguments:
 *      Required:
 *        None
 *      Optional:
 *        None
 *
 *   sample rules:
 *   alert tcp any any -> any any (msg: "DynamicRuleCheck"; );
 *
 * Effect:
 *
 *      Returns 1 if the option matches, 0 if it doesn't.
 *
 * Comments:
 *
 *
 */
#ifdef DYNAMIC_PLUGIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>

#include "debug.h"
#include "util.h"

#include "sf_dynamic_engine.h"

#include "sfghash.h"

SFGHASH *preprocRulesOptions = NULL;

typedef struct _PreprocessorOptionInfo
{
    PreprocOptionInit optionInit;
    PreprocOptionEval optionEval;
    PreprocOptionCleanup optionCleanup;
} PreprocessorOptionInfo;

void PreprocessorRuleOptionsInit()
{
    preprocRulesOptions = sfghash_new(10, 0, 0, NULL);
}

int RegisterPreprocessorRuleOption(char *optionName, PreprocOptionInit initFunc,
                                   PreprocOptionEval evalFunc,
                                   PreprocOptionCleanup cleanupFunc)
{
    int ret;
    PreprocessorOptionInfo *optionInfo;
    if (!preprocRulesOptions)
    {
        FatalError("Preprocessor Rule Option storage not initialized\n");
    }

    optionInfo = sfghash_find(preprocRulesOptions, optionName);
    if (optionInfo)
    {
        FatalError("Duplicate Preprocessor Rule Option '%s'\n", optionName);
    }

    optionInfo = (PreprocessorOptionInfo *)SnortAlloc(sizeof(PreprocessorOptionInfo));
    optionInfo->optionEval = evalFunc;
    optionInfo->optionInit = initFunc;

    ret = sfghash_add(preprocRulesOptions, optionName, optionInfo);
    if (ret != SFGHASH_OK)
    {
        FatalError("Failed to initialize Preprocessor Rule Option '%s'\n");
    }

    return 0;
}

int GetPreprocessorRuleOptionFuncs(char *optionName, void **initFunc, void **evalFunc)
{
    PreprocessorOptionInfo *optionInfo;
    if (!preprocRulesOptions)
    {
        FatalError("Preprocessor Rule Option storage not initialized\n");
    }

    optionInfo = sfghash_find(preprocRulesOptions, optionName);
    if (!optionInfo)
    {
        FatalError("Unknown Preprocessor Rule Option '%s'\n", optionName);
    }

    *initFunc = (void *)optionInfo->optionInit;
    *evalFunc = (void *)optionInfo->optionEval;

    return 0;
}

#endif /* DYNAMIC_PLUGIN */
