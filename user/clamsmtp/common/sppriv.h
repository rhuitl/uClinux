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
 
#ifndef __SPPRIV_H__
#define __SPPRIV_H__

#include "smtppass.h"

typedef struct spstate
{
    /* Settings ------------------------------- */  
    int debug_level;                /* The level to print stuff to console */
    int max_threads;                /* Maximum number of threads to process at once */
    struct timeval timeout;         /* Timeout for communication */
    int keepalives;                 /* Send server keep alives at this interval */
    int transparent;                /* Transparent proxying (input) */
    int tproxy_in;                  /* IP_TRANSPARENT for incoming conn */
    int tproxy_out;                 /* IP_TRANSPARENT for outgoing conn */
    int xclient;                    /* Send XFORWARD info */
    const char* directory;          /* The temp directory */
    const char* user;               /* User to run as */ 
    const char* pidfile;            /* The pid file for daemon */
    const char* header;             /* A header to include in the email */
    int header_prepend;             /* Prepend the header or not */
    
    struct sockaddr_any outaddr;    /* The outgoing address */
    const char* outname;
    struct sockaddr_any listenaddr; /* Address to listen on */
    const char* listenname;
    int passthrough;                /* Don't cache message data to a file */
    int precache;		    /* Size of buffer for precaching DATA for inline filtering. 0 to disable */
    const char* banner;
           
    /* State --------------------------------- */   
    const char* name;               /* The name of the program */
    int quit;                       /* Quit the process */
    int daemonized;                 /* Whether process is daemonized or not */

    /* Internal Use ------------------------- */
    char* _p;
}
spstate_t;

extern spstate_t g_state;

#endif /* __SPPRIV_H__ */

