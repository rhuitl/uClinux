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

/* Exit statuses */
#define S_NORMAL 0
#define S_UNKNOWN 1
#define S_CONNECT 2
#define S_EXCEPT 3
#define S_FATAL 4
#define S_SYNTAX 5
#define S_NONFATAL 99

typedef struct dtab {
	struct dtab *next;
	char *destname;
	struct sockaddr_in addr;
	int nclients;
	int status;
	time_t last_touched;
} dest_t;

typedef struct ptab {
	struct ptab *next;
	int pid;
	struct dtab *dest;
} proc_t;

typedef struct ctab {
	struct ctab *next;
	unsigned long addr;
	struct dtab *dest;
	int status;
	time_t last_touched;
} client_t;

void bailout (char *message, int status);
void daemonize (void);
void delete_client (client_t *client, client_t *back_ptr);
void fill_sockaddr_in (struct sockaddr_in *buffer, u_long addr, u_short port);
void forget_pid (int pid);
void init_signals (void);
void logclient (struct in_addr peer, char* status);
struct ptab *lookup_pid (int pid);
void parse_args (int ac, char **av);
int plug (int ac, char **av);
void remember_pid (int pid, struct dtab *target);
struct dtab *select_target (int clifd);
void tag_dest_bad (int pid, int status);
void waiter (int sig, SA_HANDLER_ARG2_T code, void *scp);
void inform_undertaker(int pid, int status);
void undertaker(void);
