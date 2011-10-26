/* $Id$ */
/*
 ** Copyright (C) 2005-2006 Sourcefire, Inc.
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

#include "sf_preproc_info.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preproc_lib.h"
#include "sf_dynamic_meta.h"
#include "sf_dynamic_preprocessor.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

/* Forward decl of Function that initializes/registers
 * the preproc config keywords. */
extern void DynamicInitialize();

DynamicPreprocessorData _dpd;

#define STD_BUF 1024

NORETURN void DynamicPreprocessorFatalMessage(const char *format, ...)
{
    char buf[STD_BUF];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF - 1] = '\0';

    _dpd.fatalMsg("%s", buf);

    exit(1);
}

PREPROC_LINKAGE int InitializePreprocessor(DynamicPreprocessorData *dpd)
{
    int i;
    if (dpd->version < PREPROCESSOR_DATA_VERSION)
    {
        return -1;
    }

    _dpd.version = dpd->version;
    _dpd.altBuffer = dpd->altBuffer;
    _dpd.altBufferLen = dpd->altBufferLen;
    for (i=0;i<MAX_URIINFOS;i++)
    {
        _dpd.uriBuffers[i] = dpd->uriBuffers[i];
    }
    _dpd.logMsg = dpd->logMsg;
    _dpd.errMsg = dpd->errMsg;
    _dpd.fatalMsg = dpd->fatalMsg;
    _dpd.debugMsg = dpd->debugMsg;

    _dpd.registerPreproc = dpd->registerPreproc;
    _dpd.addPreproc = dpd->addPreproc;
    _dpd.addPreprocRestart = dpd->addPreprocRestart;
    _dpd.addPreprocExit = dpd->addPreprocExit;
    _dpd.addPreprocConfCheck = dpd->addPreprocConfCheck;
    _dpd.preprocOptRegister = dpd->preprocOptRegister;
    _dpd.addPreprocProfileFunc = dpd->addPreprocProfileFunc;
    _dpd.profilingPreprocsFunc = dpd->profilingPreprocsFunc;
    _dpd.totalPerfStats = dpd->totalPerfStats;

    _dpd.alertAdd = dpd->alertAdd;
    _dpd.thresholdCheck = dpd->thresholdCheck;

    _dpd.inlineMode = dpd->inlineMode;
    _dpd.inlineDrop = dpd->inlineDrop;

    _dpd.detect = dpd->detect;
    _dpd.disableDetect = dpd->disableDetect;
    _dpd.disableAllDetect = dpd->disableAllDetect;
    _dpd.setPreprocBit = dpd->setPreprocBit;

    _dpd.streamAPI = dpd->streamAPI;
    _dpd.searchAPI = dpd->searchAPI;

    _dpd.config_file = dpd->config_file;
    _dpd.config_line = dpd->config_line;
    _dpd.printfappend = dpd->printfappend;
    _dpd.tokenSplit = dpd->tokenSplit;
    _dpd.tokenFree = dpd->tokenFree;

    _dpd.getRuleInfoByName = dpd->getRuleInfoByName;
    _dpd.getRuleInfoById = dpd->getRuleInfoById;

    DYNAMIC_PREPROC_SETUP();
    return 0;
}

PREPROC_LINKAGE int LibVersion(DynamicPluginMeta *dpm)
{

    dpm->type  = TYPE_PREPROCESSOR;
    dpm->major = MAJOR_VERSION;
    dpm->minor = MINOR_VERSION;
    dpm->build = BUILD_VERSION;
    strncpy(dpm->uniqueName, PREPROC_NAME, MAX_NAME_LEN);
    return 0;
}

/* Variables to check type of InitializeEngine and LibVersion */
//PREPROC_LINKAGE InitEngineLibFunc initEngineFunc = &InitializeEngine;
//PREPROC_LINKAGE LibVersionFunc libVersionFunc = &LibVersion;

