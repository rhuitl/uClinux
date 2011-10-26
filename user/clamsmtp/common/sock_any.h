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

#ifndef __SOCK_ANY_H__
#define __SOCK_ANY_H__

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

struct sockaddr_any
{
  union _sockaddr_any
  {
    /* The header */
    struct sockaddr a;
  
    /* The different types */
    struct sockaddr_un un;
    struct sockaddr_in in;
#ifdef HAVE_INET6
    struct sockaddr_in6 in6;
#endif
  } s;
  size_t namelen;
};

#define SANY_ADDR(any)  ((any).s.a)
#define SANY_LEN(any)   ((any).namelen)
#define SANY_TYPE(any)  ((any).s.a.sa_family)
  
int sock_any_pton(const char* addr, struct sockaddr_any* any, int opts);

/* The default port to fill in when no IP/IPv6 port specified */
#define SANY_OPT_DEFPORT(p)     (int)((p) & 0xFFFF)

/* When only port specified default to IPANY */
#define SANY_OPT_DEFANY         0x00000000

/* When only port specified default to LOCALHOST */
#define SANY_OPT_DEFLOCAL       0x00100000

/* When only port specified default to IPv6 */
#ifdef HAVE_INET6
#define SANY_OPT_DEFINET6       0x00200000
#endif

int sock_any_ntop(const struct sockaddr_any* any, char* addr, size_t addrlen, int opts);

/* Don't print or compare the port */
#define SANY_OPT_NOPORT         0x01000000

int sock_any_cmp(const struct sockaddr_any* a1, const struct sockaddr_any* a2, int opts);
 
#endif /* __SOCK_ANY_H__ */
