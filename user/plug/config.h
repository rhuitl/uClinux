/*
 * PLUGDAEMON. Copyright (c) 1997 Peter da Silva. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the program and author may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define MAX_PROXIES 32
#define MAX_CLIENTS 16384 /* These are held for a whole timeout period */
#define USAGE_FACTOR 4 /* expected # proxies per client */
#define MAX_MTU 2048	/* not strictly MTU, but size of reads and writes */

/* Random OS-Specific stuff */

#ifdef sa_sigaction
#define SA_HANDLER sa_sigaction
#else
#define SA_HANDLER sa_handler
#endif

#ifdef __OpenBSD__ 
#define SA_HANDLER_ARG2_T siginfo_t *
#endif

#ifdef __FreeBSD__
#define SA_HANDLER_ARG2_T int
#endif

#if defined(__osf__) && defined(__alpha)
#define SA_HANDLER_ARG2_T struct siginfo *
#endif

#ifndef SA_HANDLER_ARG2_T
#define SA_HANDLER_ARG2_T int
#endif                         

/* Define the name of the spawned child process which handles the actual
 * socket forwarding
 */
#define SPAWNNAME	"plug-spawn"

/* Define the path to the plug executable.
 * This is necessary because we exec ourselves to avoid vfork limitations
 */
#define PLUGPATH	"/bin/plug"
