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
 * Dynamic Library Loading for Snort
 *
 */
#ifndef _SF_DYNAMIC_PREPROCESSOR_H_
#define _SF_DYNAMIC_PREPROCESSOR_H_

#include "sf_dynamic_meta.h"

/* specifies that a function does not return
 * used for quieting Visual Studio warnings
 */
#ifdef WIN32
#if _MSC_VER >= 1400
#define NORETURN __declspec(noreturn)
#else
#define NORETURN
#endif
#else
#define NORETURN
#endif

#ifdef PERF_PROFILING
#ifndef PROFILE_PREPROCS_NOREDEF /* Don't redefine this from the main area */
#ifdef PROFILING_PREPROCS
#undef PROFILING_PREPROCS
#endif
#define PROFILING_PREPROCS _dpd.profilingPreprocsFunc()
#endif
#endif

#define PREPROCESSOR_DATA_VERSION 1

#define MINIMUM_DYNAMIC_PREPROC_ID 10000
typedef void * (*AddPreprocFunc)(void (*func)(void *, void *), unsigned short, unsigned int);
typedef void (*AddPreprocExit)(void (*func) (int, void *), void *arg, unsigned short, unsigned int);
typedef void (*AddPreprocRestart)(void (*func) (int, void *), void *arg, unsigned short, unsigned int);
typedef void *(*AddPreprocConfCheck)(void (*func) (void));
typedef int (*AlertQueueAdd)(unsigned int, unsigned int, unsigned int,
                             unsigned int, unsigned int, char *, void *);
typedef void (*PreprocRegisterFunc)(char *, void (*func)(unsigned char *));
typedef int (*ThresholdCheckFunc)(unsigned int, unsigned int, unsigned int,
                             unsigned int, long);
typedef int (*InlineFunc)();
typedef int (*InlineDropFunc)(void *);
typedef void (*DisableDetectFunc)(void *);
typedef int (*SetPreprocBitFunc)(void *, unsigned int);
typedef void (*DebugMsgFunc)(int, char *, ...);
typedef int (*DetectFunc)(void *);
typedef void *(*GetRuleInfoByNameFunc)(char *);
typedef void *(*GetRuleInfoByIdFunc)(int);
typedef int (*printfappendfunc)(char *, int, const char *, ...);
typedef char ** (*TokenSplitFunc)(char *, char *, int, int *, char);
typedef void (*TokenFreeFunc)(char ***, int);
typedef void (*AddPreprocProfileFunc)(char *, void *, int, void *);
typedef int (*ProfilingFunc)();

/* Info Data passed to dynamic preprocessor plugin must include:
 * version
 * Pointer to AltDecodeBuffer
 * Pointer to HTTP URI Buffers
 * Pointer to functions to log Messages, Errors, Fatal Errors
 * Pointer to function to add preprocessor to list of configure Preprocs
 * Pointer to function to regsiter preprocessor configuration keyword
 * Pointer to function to create preprocessor alert
 */
#include "sf_dynamic_common.h"
#include "sf_dynamic_engine.h"
#include "stream_api.h"
#include "str_search.h"

typedef struct _DynamicPreprocessorData
{
    int version;
    char *altBuffer;
    unsigned int altBufferLen;
    UriInfo *uriBuffers[MAX_URIINFOS];
    LogMsgFunc logMsg;
    LogMsgFunc errMsg;
    LogMsgFunc fatalMsg;
    DebugMsgFunc debugMsg;

    PreprocRegisterFunc registerPreproc;
    AddPreprocFunc addPreproc;
    AddPreprocRestart addPreprocRestart;
    AddPreprocExit addPreprocExit;
    AddPreprocConfCheck addPreprocConfCheck;
    RegisterPreprocRuleOpt preprocOptRegister;
    AddPreprocProfileFunc addPreprocProfileFunc;
    ProfilingFunc profilingPreprocsFunc;
    void *totalPerfStats;

    AlertQueueAdd alertAdd;
    ThresholdCheckFunc thresholdCheck;

    InlineFunc  inlineMode;
    InlineDropFunc  inlineDrop;

    DetectFunc detect;
    DisableDetectFunc disableDetect;
    DisableDetectFunc disableAllDetect;

    SetPreprocBitFunc setPreprocBit;

    StreamAPI *streamAPI;
    SearchAPI *searchAPI;

    char **config_file;
    int *config_line;
    printfappendfunc printfappend;
    TokenSplitFunc tokenSplit;
    TokenFreeFunc tokenFree;

    GetRuleInfoByNameFunc getRuleInfoByName;
    GetRuleInfoByIdFunc getRuleInfoById;

} DynamicPreprocessorData;

/* Function prototypes for Dynamic Preprocessor Plugins */
void CloseDynamicPreprocessorLibs();
int LoadDynamicPreprocessor(char *library_name, int indent);
void LoadAllDynamicPreprocessors(char *path);
typedef int (*InitPreprocessorLibFunc)(DynamicPreprocessorData *);

int InitDynamicPreprocessors();
void RemoveDuplicatePreprocessorPlugins();

/* This was necessary because of static code analysis not recognizing that
 * fatalMsg did not return - use instead of fatalMsg
 */
NORETURN void DynamicPreprocessorFatalMessage(const char *format, ...);

#endif /* _SF_DYNAMIC_PREPROCESSOR_H_ */
