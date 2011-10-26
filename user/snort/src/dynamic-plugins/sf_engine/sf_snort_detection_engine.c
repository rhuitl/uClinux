/*
 * sf_snort_detection_engine.c
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
 * Author: Steve Sturges
 *         Andy  Mullican
 *
 * Date: 5/2005
 *
 * Dyanmic Rule Engine
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdarg.h>
#include "sf_snort_packet.h"
#include "sf_snort_plugin_api.h"
#include "sf_dynamic_meta.h"
#include "sf_dynamic_engine.h"

#define MAJOR_VERSION   1
#define MINOR_VERSION   6
#define BUILD_VERSION   11
#define DETECT_NAME     "SF_SNORT_DETECTION_ENGINE"

#ifdef WIN32
#define PATH_MAX MAX_PATH
#else
#include <sys/param.h>
#include <limits.h>
#endif

#define DEBUG_WRAP(x)

DynamicEngineData _ded;

#define STD_BUF 1024

NORETURN void DynamicEngineFatalMessage(const char *format, ...)
{
    char buf[STD_BUF];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF - 1] = '\0';

    _ded.fatalMsg("%s", buf);

    exit(1);
}


extern int BoyerContentSetup(Rule *rule, ContentInfo *content);
extern int PCRESetup(Rule *rule, PCREInfo *pcreInfo);
extern int ValidateHeaderCheck(Rule *rule, HdrOptCheck *optData);
extern void ContentSetup(void);
extern int ByteExtractInitialize(Rule *rule, ByteExtract *extractData);
extern int LoopInfoInitialize(Rule *rule, LoopInfo *loopInfo);

ENGINE_LINKAGE int InitializeEngine(DynamicEngineData *ded)
{
    int i;
    if (ded->version < ENGINE_DATA_VERSION)
    {
        return -1;
    }

    _ded.version = ded->version;
    _ded.altBuffer = ded->altBuffer;
    for (i=0;i<MAX_URIINFOS;i++)
    {
        _ded.uriBuffers[i] = ded->uriBuffers[i];
    }
    _ded.ruleRegister = ded->ruleRegister;
    _ded.flowbitRegister = ded->flowbitRegister;
    _ded.flowbitCheck = ded->flowbitCheck;
    _ded.asn1Detect = ded->asn1Detect;
    _ded.dataDumpDirectory = ded->dataDumpDirectory;
    _ded.logMsg = ded->logMsg;
    _ded.errMsg = ded->errMsg;
    _ded.fatalMsg = ded->fatalMsg;
    _ded.getPreprocOptFuncs = ded->getPreprocOptFuncs;

    return 0;
}

ENGINE_LINKAGE int LibVersion(DynamicPluginMeta *dpm)
{

    dpm->type  = TYPE_ENGINE;
    dpm->major = MAJOR_VERSION;
    dpm->minor = MINOR_VERSION;
    dpm->build = BUILD_VERSION;
    strncpy(dpm->uniqueName, DETECT_NAME, MAX_NAME_LEN);
    return 0;
}

/* Variables to check type of InitializeEngine and LibVersion */
ENGINE_LINKAGE InitEngineLibFunc initEngineFunc = &InitializeEngine;
ENGINE_LINKAGE LibVersionFunc libVersionFunc = &LibVersion;


/* Evaluates the rule -- indirect interface, this will be
 * called from the SpecialPurpose detection plugin as
 * CheckRule (void *, void *);
 */
int CheckRule(void *p, void *r)
{
    Rule *rule = (Rule *)r;
    if (!rule->initialized)
    {
        _ded.errMsg("Dynamic Rule [%d:%d] was not initialized properly.\n",
            rule->info.genID, rule->info.sigID);
        return RULE_NOMATCH;
    }

    ContentSetup();

    /* If there is an eval func, use it, this is a 'hand-coded' rule */
    if (rule->evalFunc)
        return rule->evalFunc((SFSnortPacket *)p);
    else
        return ruleMatch(p, rule);
}

int HasFlow(void *r)
{
    Rule *rule = (Rule *)r;
    RuleOption *option;
    int i;

    if ((!rule) || (!rule->initialized))
    {
        return 0;
    }

    for (i=0,option = rule->options[i];option != NULL; option = rule->options[++i])
    {
        if (option->optionType == OPTION_TYPE_FLOWFLAGS)
        {
            return 1;
        }
    }

    return 0;
}

int HasFlowBits(void *r)
{
    Rule *rule = (Rule *)r;
    RuleOption *option;
    int i;

    if ((!rule) || (!rule->initialized))
    {
        return 0;
    }

    for (i=0,option = rule->options[i];option != NULL; option = rule->options[++i])
    {
        if (option->optionType == OPTION_TYPE_FLOWBIT)
        {
            return 1;
        }
    }

    return 0;
}

int GetFPContent(void *r, int buf, FPContentInfo** contents, int maxNumContents)
{
    Rule *rule = (Rule *)r;
    int i, j = 0;
    RuleOption *option;
    int numContents = 0;

    for (i=0,option = rule->options[i];option != NULL; option = rule->options[++i])
    {
        if (option->optionType == OPTION_TYPE_CONTENT)
        {
            if ((option->option_u.content->flags & CONTENT_FAST_PATTERN) &&
                (((option->option_u.content->flags & (CONTENT_BUF_URI | CONTENT_BUF_POST)) && (buf == FASTPATTERN_URI)) ||
                 (!(option->option_u.content->flags & (CONTENT_BUF_URI | CONTENT_BUF_POST)) && (buf == FASTPATTERN_NORMAL)) ))
            {
                FPContentInfo *content = (FPContentInfo *)calloc(1, sizeof(FPContentInfo));
                if (content == NULL)
                {
                    DynamicEngineFatalMessage("Failed to allocate memory\n");
                }

                content->content = option->option_u.content->patternByteForm;
                content->length = option->option_u.content->patternByteFormLength;
                content->noCaseFlag = (char)(option->option_u.content->flags & CONTENT_NOCASE);

                contents[j++] = content;
                numContents++;
            }
        }
        if (numContents >= maxNumContents)
            break;
    }
    
    return numContents;
}

static int DecodeContentPattern(Rule *rule, ContentInfo *content)
{
    int pat_len;
    char *pat_begin = content->pattern;
    char *pat_idx;
    char *pat_end;
    unsigned char tmp_buf[2048];
    char *raw_idx;
    char *raw_end;
    int tmp_len = 0;
    int hex_encoding = 0;
    int hex_len = 0;
    int pending = 0;
    int char_count = 0;
    int escaped = 0;

    char hex_encoded[3];


    /* First, setup the raw data by parsing content */
    /* XXX: Basically, duplicate the code from ParsePattern()
     * in sp_pattern_match.c */
    pat_len = strlen(content->pattern);
    pat_end = pat_begin + pat_len;

    /* set the indexes into the temp buffer */
    raw_idx = tmp_buf;
    raw_end = (raw_idx + pat_len);

    /* why is this buffer so small? */
    memset(hex_encoded, 0, 3);
    memset(hex_encoded, '0', 2);

    pat_idx = pat_begin;

    /* Uggh, loop through each char */
    while(pat_idx < pat_end)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "processing char: %c\n", *pat_idx););
        switch(*pat_idx)
        {
            case '|':
                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got bar... "););
                if(!escaped)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "not in literal mode... "););
                    if(!hex_encoding)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Entering hexmode\n"););
                        hex_encoding = 1;
                    }
                    else
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Exiting hexmode\n"););

                        /*
                        **  Hexmode is not even.
                        */
                        if(!hex_len || hex_len % 2)
                        {
                            DynamicEngineFatalMessage("Content hexmode argument has invalid "
                                                      "number of hex digits for dynamic rule [%d:%d].\n", 
                                                      rule->info.genID, rule->info.sigID);
                        }

                        hex_encoding = 0;
                        pending = 0;
                    }

                    if(hex_encoding)
                        hex_len = 0;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "literal set, Clearing\n"););
                    escaped = 0;
                    tmp_buf[tmp_len] = pat_begin[char_count];
                    tmp_len++;
                }

                break;

            case '\\':
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Got literal char... "););

                if(!escaped)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Setting literal\n"););

                    escaped = 1;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Clearing literal\n"););
                    tmp_buf[tmp_len] = pat_begin[char_count];
                    escaped = 0;
                    tmp_len++;
                }

                break;
            case '"':
                if (!escaped)
                {
                    DynamicEngineFatalMessage("Non-escaped '\"' character in dynamic rule [%d:%d]!\n",
                                              rule->info.genID, rule->info.sigID);
                }
                /* otherwise process the character as default */
            default:
                if(hex_encoding)
                {
                    if(isxdigit((int) *pat_idx))
                    {
                        hex_len++;

                        if(!pending)
                        {
                            hex_encoded[0] = *pat_idx;
                            pending++;
                        }
                        else
                        {
                            hex_encoded[1] = *pat_idx;
                            pending--;

                            if(raw_idx < raw_end)
                            {                            
                                tmp_buf[tmp_len] = (u_char) 
                                    strtol(hex_encoded, (char **) NULL, 16)&0xFF;

                                tmp_len++;
                                memset(hex_encoded, 0, 3);
                                memset(hex_encoded, '0', 2);
                            }
                            else
                            {
                                DynamicEngineFatalMessage("ParsePattern() buffer overflow, "
                                                          "make a smaller pattern please for dynamic "
                                                          "rule [%d:%d]! (Max size = 2048)\n",
                                                          rule->info.genID, rule->info.sigID);
                            }
                        }
                    }
                    else
                    {
                        if(*pat_idx != ' ')
                        {
                            DynamicEngineFatalMessage("What is this \"%c\"(0x%X) doing in your "
                                                      "binary buffer for dynamic rule [%d:%d]? "
                                                      "Valid hex values only please! "
                                                      "(0x0 - 0xF) Position: %d\n",
                                                      (char) *pat_idx, (char) *pat_idx, 
                                                      rule->info.genID, rule->info.sigID, char_count);
                        }
                    }
                }
                else
                {
                    if(*pat_idx >= 0x1F && *pat_idx <= 0x7e)
                    {
                        if(raw_idx < raw_end)
                        {
                            tmp_buf[tmp_len] = pat_begin[char_count];
                            tmp_len++;
                        }
                        else
                        {
                            DynamicEngineFatalMessage("ParsePattern() buffer overflow in "
                                                      "dynamic rule [%d:%d]!\n",
                                                      rule->info.genID, rule->info.sigID);
                        }

                        if(escaped)
                        {
                            escaped = 0;
                        }
                    }
                    else
                    {
                        if(escaped)
                        {
                            tmp_buf[tmp_len] = pat_begin[char_count];
                            tmp_len++;
                            DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Clearing literal\n"););
                            escaped = 0;
                        }
                        else
                        {
                            DynamicEngineFatalMessage("character value out of range, try a "
                                                      "binary buffer for dynamic rule [%d:%d]\n", 
                                                      rule->info.genID, rule->info.sigID);
                        }
                    }
                }

                break;
        }

        raw_idx++;
        pat_idx++;
        char_count++;
    }
    
    /* Now, tmp_buf contains the decoded ascii & raw binary from the patter */
    content->patternByteForm = (u_int8_t *)calloc(tmp_len, sizeof(u_int8_t));
    if (content->patternByteForm == NULL)
    {
        DynamicEngineFatalMessage("Failed to allocate memory\n");
    }

    memcpy(content->patternByteForm, tmp_buf, tmp_len);
    content->patternByteFormLength = tmp_len;

    return 0;
}

static unsigned int getNonRepeatingLength(char *data, int data_len)
{
    int i, j;
    
    j = 0;
    for ( i = 1; i < data_len; i++ )
    {
        if ( data[j] != data[i] )
        {
            j = 0;
            continue;
        }
        if ( i == (data_len - 1) )
        {
            return (data_len - j - 1);
        }
        j++;
    }
    return data_len;
}

int RegisterOneRule(Rule *rule, int registerRule)
{
    int i;
    int fpContentFlags = 0;
    int result;
    RuleOption *option;
    unsigned long longestContent = 0;
    int longestContentIndex = -1;
    for (i=0;rule->options[i] != NULL; i++)
    {
        option = rule->options[i];
        switch (option->optionType)
        {
        case OPTION_TYPE_CONTENT:
            {
                ContentInfo *content = option->option_u.content;
                DecodeContentPattern(rule, content);
                BoyerContentSetup(rule, content);
                if (content->flags & CONTENT_FAST_PATTERN)
                {
                    if (content->flags & (CONTENT_BUF_URI | CONTENT_BUF_POST))
                        fpContentFlags |= FASTPATTERN_URI;
                    else
                        fpContentFlags |= FASTPATTERN_NORMAL;
                }
                content->incrementLength =
                    getNonRepeatingLength(content->patternByteForm, content->patternByteFormLength);

                if (content->patternByteFormLength > longestContent)
                {
                    longestContent = content->patternByteFormLength;
                    longestContentIndex = i;
                }
            }
            break;
        case OPTION_TYPE_PCRE:
            {
                PCREInfo *pcre = option->option_u.pcre;
                if (PCRESetup(rule, pcre))
                {
                    break;
                }
            }
            break;
        case OPTION_TYPE_FLOWBIT:
            {
                FlowBitsInfo *flowbits = option->option_u.flowBit;
                flowbits->id = _ded.flowbitRegister(flowbits->flowBitsName, 0);
                if (flowbits->operation & FLOWBIT_NOALERT)
                    rule->noAlert = 1;
            }
            break;
        case OPTION_TYPE_ASN1:
            /*  Call asn1_init_mem(512); if linking statically to asn source */
            break;
        case OPTION_TYPE_HDR_CHECK:
            {
                HdrOptCheck *optData = option->option_u.hdrData;
                result = ValidateHeaderCheck(rule, optData);
                if (result)
                {
                    /* Don't initialize this rule */
                    rule->initialized = 0;
                    return result;
                }
            }
            break;
        case OPTION_TYPE_BYTE_EXTRACT:
            {
                ByteExtract *extractData = option->option_u.byteExtract;
                result = ByteExtractInitialize(rule, extractData);
                if (result)
                {
                    /* Don't initialize this rule */
                    rule->initialized = 0;
                    return result;
                }
            }
            break;
        case OPTION_TYPE_LOOP:
            {
                LoopInfo *loopInfo = option->option_u.loop;
                result = LoopInfoInitialize(rule, loopInfo);
                if (result)
                {
                    /* Don't initialize this rule */
                    rule->initialized = 0;
                    return result;
                }
                loopInfo->initialized = 1;
            }
            break;
        case OPTION_TYPE_PREPROCESSOR:
            {
                PreprocessorOption *preprocOpt = option->option_u.preprocOpt;
                PreprocOptionInit optionInit;
                result = _ded.getPreprocOptFuncs(preprocOpt->optionName,
                    &preprocOpt->optionInit, &preprocOpt->optionEval);
                if (result)
                {
                    /* Don't initialize this rule */
                    rule->initialized = 0;
                    return result;
                }

                optionInit = (PreprocOptionInit)preprocOpt->optionInit;
                result = optionInit(preprocOpt->optionName,
                    preprocOpt->optionParameters, &preprocOpt->dataPtr);
                if (result)
                {
                    /* Don't initialize this rule */
                    rule->initialized = 0;
                    return result;
                }
            }
            break;

        case OPTION_TYPE_BYTE_TEST:
        case OPTION_TYPE_BYTE_JUMP:
        default:
            /* nada */
            break;
        }
    }

    /* If no options were marked as the fast pattern,
     * use the longest one we found.
     */
    if ((fpContentFlags == 0) && (longestContentIndex != -1))
    {
        option = rule->options[longestContentIndex];
        /* Just to be safe, make sure this is a content option */
        if (option->optionType == OPTION_TYPE_CONTENT)
        {
            ContentInfo *content = option->option_u.content;

            if (content->flags & (CONTENT_BUF_URI | CONTENT_BUF_POST))
                fpContentFlags |= FASTPATTERN_URI;
            else
                fpContentFlags |= FASTPATTERN_NORMAL;

            content->flags |= CONTENT_FAST_PATTERN;
        }
    }

    if (registerRule)
    {
        /* Allocate an OTN and link it in with snort */
        _ded.ruleRegister(rule->info.sigID,
                                   rule->info.genID,
                                   (void *)rule,
                                   &CheckRule,
                                   &HasFlow,
                                   &HasFlowBits,
                                   fpContentFlags,
                                   &GetFPContent);
    }

    rule->initialized = 1;

    /* Index less one since we've iterated through them already */
    rule->numOptions = i;

    return 0;
}

#define TCP_STRING "tcp"
#define UDP_STRING "udp"
#define ICMP_STRING "icmp"
#define IP_STRING "ip"
char *GetProtoString(int protocol)
{
    switch (protocol)
    {
    case IPPROTO_TCP:
        return TCP_STRING;
    case IPPROTO_UDP:
        return UDP_STRING;
    case IPPROTO_ICMP:
        return ICMP_STRING;
    default:
        break;
    }
    return IP_STRING;
}

static int DumpRule(FILE *fp, Rule *rule)
{
    RuleReference *ref;
    int i;

    fprintf(fp, "alert %s %s %s %s %s %s ",
        GetProtoString(rule->ip.protocol),
        rule->ip.src_addr, rule->ip.src_port,
        rule->ip.direction == 0 ? "->" : "<>",
        rule->ip.dst_addr, rule->ip.dst_port);
    fprintf(fp, "(msg:\"%s\"; ", rule->info.message);
    fprintf(fp, "metadata: engine shared, soid %d|%d; ",
            rule->info.genID, rule->info.sigID);
    fprintf(fp, "sid:%d; ", rule->info.sigID);
    fprintf(fp, "gid:%d; ", rule->info.genID);
    fprintf(fp, "rev:%d; ", rule->info.revision);
    fprintf(fp, "classtype:%s; ", rule->info.classification);
    if (rule->info.priority != 0)
        fprintf(fp, "priority:%d; ", rule->info.priority);

    if (rule->info.references)
    {
        for (i=0,ref = rule->info.references[i];
             ref != NULL;
             i++,ref = rule->info.references[i])
        {
            fprintf(fp, "reference:%s,%s; ", ref->systemName, ref->refIdentifier);
        }
    }

    fprintf(fp, ")\n");

    return 0;
}

ENGINE_LINKAGE int RegisterRules(Rule **rules)
{
    int i;

    for (i=0; rules[i] != NULL; i++)
    {
        RegisterOneRule(rules[i], REGISTER_RULE);
    }

    return 0;
}

ENGINE_LINKAGE int DumpRules(char *rulesFileName, Rule **rules)
{
    FILE *ruleFP;
    char ruleFile[PATH_MAX+1];
    int i;
#ifndef WIN32
#define DIR_SEP "/"
#else
#define DIR_SEP "\\"
#define snprintf _snprintf
#endif

    /* XXX: Need to do some checking here on lengths */
    ruleFile[0] = '\0';
    if ((strlen(_ded.dataDumpDirectory) + strlen(DIR_SEP) + strlen(rulesFileName) + strlen(".rules")) > PATH_MAX)
        return -1;

    snprintf(ruleFile, PATH_MAX, "%s%s%s.rules", _ded.dataDumpDirectory, DIR_SEP, rulesFileName);
    ruleFile[PATH_MAX] = '\0';
    ruleFP = fopen(ruleFile, "w");
    if (ruleFP)
    {
        fprintf(ruleFP, "# Autogenerated skeleton rules file.  Do NOT edit by hand\n");
        for (i=0; rules[i] != NULL; i++)
        {
            DumpRule(ruleFP, rules[i]);
        }
        fclose(ruleFP);
    }
    else
    {
        return -1;
    }

    return 0;
}
