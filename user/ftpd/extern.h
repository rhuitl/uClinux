/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)extern.h	8.2 (Berkeley) 4/4/94
 */

#include <stdio.h>
#include <setjmp.h>
#include <sys/types.h>
#include <unistd.h>

extern void cwd            __P ((const char *));
extern int  checkuser      __P ((const char *filename, const char *name));
extern void delete         __P ((const char *));
extern int  display_file   __P ((const char *name, int code));
extern void dologout       __P ((int));
extern void fatal          __P ((const char *));
extern int  ftpd_pclose    __P ((FILE *));
extern FILE *ftpd_popen    __P ((char *, const char *));
#if !HAVE_DECL_GETUSERSHELL
extern char *getusershell  __P ((void));
#endif
extern void logwtmp        __P ((const char *, const char *, const char *));
extern void lreply         __P ((int, const char *, ...));
extern void makedir        __P ((const char *));
extern void nack           __P ((const char *));
extern void pass           __P ((const char *));
extern void passive        __P ((void));
extern void perror_reply   __P ((int, const char *));
extern void pwd            __P ((void));
extern void removedir      __P ((const char *));
extern void renamecmd      __P ((const char *, const char *));
extern char *renamefrom    __P ((const char *));
extern void reply          __P ((int, const char *, ...));
extern void retrieve       __P ((const char *, const char *));
extern void send_file_list __P ((const char *));
extern void setproctitle   __P ((const char *, ...));
extern void statcmd        __P ((void));
extern void statfilecmd    __P ((const char *));
extern void store          __P ((const char *, const char *, int));
extern void toolong        __P ((int));
extern char *telnet_fgets  __P ((char *, int, FILE *));
extern void upper          __P ((char *));
extern void user           __P ((const char *));
extern char *sgetsave      __P ((const char *));

/* Exported from ftpd.c.  */
extern jmp_buf  errcatch;
extern struct sockaddr_in data_dest;
extern struct sockaddr_in his_addr;
extern int logged_in;
extern struct passwd *pw;
extern int guest;
extern int logging;
extern int type;
extern int form;
extern int debug;
extern int timeout;
extern int maxtimeout;
extern int pdata;
extern char *hostname;
extern char *remotehost;
extern char proctitle[];
extern int usedefault;
extern char tmpline[];

/* Exported from ftpcmd.y.  */
extern off_t restart_point;

/* Exported from server_mode.c.  */
extern int server_mode __P ((const char *pidfile,
			     struct sockaddr_in *phis_addr));

/* Credential for the request.  */
struct credentials
{
  char *name;
  char *homedir;
  char *rootdir;
  char *shell;
  char *remotehost;
  char *passwd;
  char *pass;
  char *message; /* Sending back custom messages.  */
  uid_t uid;
  gid_t gid;
  int guest;
  int dochroot;
  int logged_in;
#define AUTH_TYPE_PASSWD    0
#define AUTH_TYPE_PAM       1
#define AUTH_TYPE_KERBEROS  2
#define AUTH_TYPE_KERBEROS5 3
#define AUTH_TYPE_OPIE      4
  int auth_type;
};

extern struct credentials cred;
extern int  sgetcred       __P ((const char *, struct credentials *));
extern int  auth_user      __P ((const char *, struct credentials *));
extern int  auth_pass      __P ((const char *, struct credentials *));

/* Exported from pam.c */
#ifdef WITH_PAM
extern int  pam_user       __P ((const char *, struct credentials *));
extern int  pam_pass       __P ((const char *, struct credentials *));
#endif

/* Extract or fake data from a `struct stat'.
   ST_BLKSIZE: Optimal I/O blocksize for the file, in bytes. */
#ifndef HAVE_STRUCT_STAT_ST_BLKSIZE
# define ST_BLKSIZE(statbuf) DEV_BSIZE
#else /* HAVE_STRUCT_STAT_ST_BLKSIZE */
/* Some systems, like Sequents, return st_blksize of 0 on pipes. */
# define ST_BLKSIZE(statbuf) ((statbuf).st_blksize > 0 \
                              ? (statbuf).st_blksize : DEV_BSIZE)
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */

