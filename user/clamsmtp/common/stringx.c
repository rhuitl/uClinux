/*
 * Copyright (c) 2004, Nate Nielsen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 * 
 *     * Redistributions of source code must retain the above 
 *       copyright notice, this list of conditions and the 
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the 
 *       above copyright notice, this list of conditions and 
 *       the following disclaimer in the documentation and/or 
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be 
 *       used to endorse or promote products derived from this 
 *       software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
 * DAMAGE.
 * 
 *
 * CONTRIBUTORS
 *  Nate Nielsen <nielsen@memberwebs.com>
 *
 */ 

#include <sys/types.h>

#include <ctype.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "usuals.h"
#include "compat.h"
#include "stringx.h"

/* ----------------------------------------------------------------------------------
 *  Parsing
 */

int is_first_word(const char* line, const char* word, int len)
{
    ASSERT(line);
    ASSERT(word);
    ASSERT(len > 0);
    
    while(*line && isspace(*line))
        line++;

    if(strncasecmp(line, word, len) != 0)
        return 0;

    line += len;
    return !*line || isspace(*line);
}

int check_first_word(const char* line, const char* word, int len, char* delims)
{
    const char* t;
    int found = 0;
    
    ASSERT(line);
    ASSERT(word);
    ASSERT(len > 0);
    
    t = line;
    
    while(*t && strchr(delims, *t))
        t++;

    if(strncasecmp(t, word, len) != 0)
        return 0;

    t += len;
    
    while(*t && strchr(delims, *t))
    {
        found = 1;
        t++;
    }
    
    return (!*t || found) ? t - line : 0;
}

int is_last_word(const char* line, const char* word, int len)
{
    const char* t;
    
    ASSERT(line);
    ASSERT(word);
    ASSERT(len > 0);

    t = line + strlen(line);
    
    while(t > line && isspace(*(t - 1)))
        --t;
    
    if(t - len < line)
        return 0;
        
    return strncasecmp(t - len, word, len) == 0;
}

int is_blank_line(const char* line)
{
    /* Small optimization */
    if(!*line)
        return 1;
    
    while(*line && isspace(*line))
        line++;
        
    return *line == 0;
}

char* trim_start(const char* data)
{
    while(*data && isspace(*data))
        ++data;
    return (char*)data;
}

char* trim_end(char* data)
{
    char* t = data + strlen(data);
  
    while(t > data && isspace(*(t - 1)))
    {
        t--;
        *t = 0;
    }
  
    return data;
}

char* trim_space(char* data)
{
    data = (char*)trim_start(data);
    return trim_end(data);
}

/* String to bool helper function */
int strtob(const char* str)
{
    if(strcasecmp(str, "0") == 0 ||
       strcasecmp(str, "no") == 0 ||
       strcasecmp(str, "false") == 0 ||
       strcasecmp(str, "f") == 0 ||
       strcasecmp(str, "off") == 0)
        return 0;
    
    if(strcasecmp(str, "1") == 0 ||
       strcasecmp(str, "yes") == 0 ||
       strcasecmp(str, "true") == 0 ||
       strcasecmp(str, "t") == 0 ||
       strcasecmp(str, "on") == 0)
        return 1;

    return -1;  
}
