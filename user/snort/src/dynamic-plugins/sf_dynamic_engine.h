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
#ifndef _SF_DYNAMIC_ENGINE_H_
#define _SF_DYNAMIC_ENGINE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef WIN32
#include <sys/types.h>
#else
#include <stdint.h>
#endif

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

/* Function prototype used to evaluate a special OTN */
/* Parameters are packet pointer & rule info pointer */
typedef int (*OTNCheckFunction)(void *, void *);
typedef int (*OTNHasFlowFunction)(void *);

/* Data struct & function prototype used to get list of
 * Fast Pattern Content information. */
typedef struct _FPContentInfo
{
    int length;
    char *content;
    char noCaseFlag;
} FPContentInfo;
/* Parameters are rule info pointer, int to indicate URI or NORM,
 * and list pointer */
#define FASTPATTERN_NORMAL 0x01
#define FASTPATTERN_URI    0x02
typedef int (*GetFPContentFunction)(void *, int, FPContentInfo**, int);

/* ruleInfo is passed to OTNCheckFunction when the fast pattern matches. */
typedef int (*RegisterRule)(u_int32_t, u_int32_t, void *, OTNCheckFunction,
                            OTNHasFlowFunction, OTNHasFlowFunction, int,
                            GetFPContentFunction);
typedef u_int32_t (*RegisterBit)(char *, int);
typedef int (*CheckFlowbit)(void *, int, u_int32_t);
typedef int (*DetectAsn1)(void *, void *, u_int8_t *);
typedef void (*LogMsg)(const char *, ...);
typedef int (*PreprocOptionEval)(void *p, u_int8_t **cursor, void *dataPtr);
typedef int (*PreprocOptionInit)(char *, char *, void **dataPtr);
typedef void (*PreprocOptionCleanup)(void *dataPtr);
typedef int (*RegisterPreprocRuleOpt)(char *, PreprocOptionInit, PreprocOptionEval, PreprocOptionCleanup);
typedef int (*GetPreprocRuleOptFuncs)(char *, void **, void **);

/* Info Data passed to dynamic engine plugin must include:
 * version
 * Pointer to AltDecodeBuffer
 * Pointer to HTTP URI Buffers
 * Pointer to function to register C Rule
 * Pointer to function to register C Rule flowbits
 * Pointer to function to check flowbit
 * Pointer to function to do ASN1 Detection
 * Pointer to functions to log Messages, Errors, Fatal Errors
 * Directory path
 */
#include "sf_dynamic_common.h"

#define ENGINE_DATA_VERSION 2

typedef struct _DynamicEngineData
{
    int version;
    char *altBuffer;
    UriInfo *uriBuffers[MAX_URIINFOS];
    RegisterRule ruleRegister;
    RegisterBit flowbitRegister;
    CheckFlowbit flowbitCheck;
    DetectAsn1 asn1Detect;
    LogMsg logMsg;
    LogMsg errMsg;
    LogMsg fatalMsg;
    char *dataDumpDirectory;

    GetPreprocRuleOptFuncs getPreprocOptFuncs;
} DynamicEngineData;

/* Function prototypes for Dynamic Engine Plugins */
void CloseDynamicEngineLibs();
void LoadAllDynamicEngineLibs(char *path);
int LoadDynamicEngineLib(char *library_name, int indent);
typedef int (*InitEngineLibFunc)(DynamicEngineData *);

int InitDynamicEngines();
void RemoveDuplicateEngines();

int DumpDetectionLibRules();

/* This was necessary because of static code analysis not recognizing that
 * fatalMsg did not return - use instead of fatalMsg
 */
NORETURN void DynamicEngineFatalMessage(const char *format, ...);

#endif /* _SF_DYNAMIC_ENGINE_H_ */
