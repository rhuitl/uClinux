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
 *  Andreas Steinmetz <ast@domdv.de>
 *  Rubio Vaughan <rubio@passim.net>
 *  Olivier Beyssac <ob@r14.freenix.org>
 */ 

#include <config/autoconf.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <pwd.h>
#include <time.h>

#include "usuals.h"

#ifdef LINUX_TRANSPARENT_PROXY
#include <netinet/in.h>
#include <linux/netfilter_ipv4.h>
#endif

#include "compat.h"
#include "sock_any.h"
#include "stringx.h"
#include "sppriv.h"

/* -----------------------------------------------------------------------
 *  STRUCTURES
 */

typedef struct spthread
{
    pthread_t tid;      /* Written to by the main thread */
    int fd;             /* The file descriptor or -1 */
}
spthread_t;

/* -----------------------------------------------------------------------
 *  DATA
 */

#define CRLF                "\r\n"

#define SMTP_TOOLONG        "500 Line too long" CRLF
#define SMTP_STARTBUSY      "554 Server Busy" CRLF
#define SMTP_STARTFAILED    "554 Local Error" CRLF
#define SMTP_DATAINTERMED   "354 Start mail input; end with <CRLF>.<CRLF>" CRLF
#define SMTP_FAILED         "451 Local Error" CRLF
#define SMTP_NOTSUPP        "502 Command not implemented" CRLF
#define SMTP_NOTAUTH        "554 Insufficient authorization" CRLF
#define SMTP_OK             "250 Ok" CRLF
#define SMTP_REJPREFIX      "550 Content Rejected; "

#define SMTP_DATA           "DATA" CRLF
#define SMTP_NOOP           "NOOP" CRLF
#define SMTP_XCLIENT        "XCLIENT ADDR=%s" CRLF
#define BANNER_PREFIX       "220 "
#define HELO_PREFIX         "250 "
#define EHLO_PREFIX         "250-"
#define SMTP_BANNER         "220 smtp.passthru" CRLF
#define SMTP_HELO_RSP       "250 smtp.passthru" CRLF
#define SMTP_EHLO_RSP       "250-smtp.passthru" CRLF
#define SMTP_FEAT_RSP       "250 XFILTERED" CRLF
#define SMTP_DELIMS         "\r\n\t :"
#define SMTP_MULTI_DELIMS   " -"

#define ESMTP_PIPELINE      "PIPELINING"
#define ESMTP_TLS           "STARTTLS"
#define ESMTP_CHUNK         "CHUNKING"
#define ESMTP_BINARY        "BINARYMIME"
#define ESMTP_CHECK         "CHECKPOINT"
#define ESMTP_XCLIENT       "XCLIENT"

#define HELO_CMD            "HELO"
#define EHLO_CMD            "EHLO"
#define FROM_CMD            "MAIL FROM"
#define TO_CMD              "RCPT TO"
#define DATA_CMD            "DATA"
#define RSET_CMD            "RSET"
#define STARTTLS_CMD        "STARTTLS"
#define BDAT_CMD            "BDAT"
#define XCLIENT_CMD         "XCLIENT"

#define DATA_END_SIG        "." CRLF

#define DATA_RSP            "354"
#define OK_RSP              "250"
#define START_RSP           "220"

#define RCVD_HEADER         "Received:"

/* The set of delimiters that can be present between config and value */
#define CFG_DELIMS      	": \t"

/* Maximum length of the header argument */
#define MAX_HEADER_LENGTH 	1024

/*
 * asctime_r manpage: "stores the string in a user-supplied buffer of
 * length at least 26".  We'll need some more bytes to put timezone
 * information behind
 */
#define MAX_DATE_LENGTH 	64

#define LINE_TOO_LONG(l)    ((l) >= (SP_LINE_LENGTH - 2))

/* -----------------------------------------------------------------------
 *  CONFIGURATION OPTIONS
 * 
 * - Be sure that your configuration option needs to go into this 
 *   file. More likely it'll go into clamsmtpd.c 
 * - When adding configuration options follow the instructions in 
 *   clamsmtpd.c, except add option to spstate_t (sppriv.h) and parse in 
 *   sp_parse_option (below)
 */
 
#define CFG_MAXTHREADS      "MaxConnections"
#define CFG_TIMEOUT         "TimeOut"
#define CFG_OUTADDR         "OutAddress"
#define CFG_LISTENADDR      "Listen"
#define CFG_HEADER      	"Header"
#define CFG_TRANSPARENT     "TransparentProxy"
#ifdef LINUX_TRANSPARENT_PROXY
#define CFG_TPROXYIN        "TProxyIn"
#define CFG_TPROXYOUT       "TProxyOut"
#endif
#define CFG_PASSTHROUGH     "Passthrough"
#define CFG_PRECACHE        "Precache"
#define CFG_DIRECTORY       "TempDirectory"
#define CFG_KEEPALIVES      "KeepAlives"
#define CFG_USER            "User"
#define CFG_PIDFILE         "PidFile"
#define CFG_XCLIENT         "XClient"
#define	CFG_BANNER          "Banner"

/* -----------------------------------------------------------------------
 *  DEFAULT SETTINGS
 */

#define DEFAULT_SOCKET  "10025"
#define DEFAULT_PORT    10025
#define DEFAULT_MAXTHREADS  64
#define DEFAULT_TIMEOUT   180
#define DEFAULT_KEEPALIVES 0

/* -----------------------------------------------------------------------
 *  GLOBALS
 */

spstate_t g_state;                          /* The state and configuration of the daemon */
unsigned int g_unique_id = 0x00100000;      /* For connection ids */
pthread_mutex_t g_mutex;                    /* The main mutex */
pthread_mutexattr_t g_mtxattr;
 
/* -----------------------------------------------------------------------
 *  FORWARD DECLARATIONS
 */

static void on_quit(int signal);
static void drop_privileges();
static void fix_owner(int fd);
static void pid_file(int write);
static void connection_loop(int sock);
static void* thread_main(void* arg);
static int smtp_passthru(spctx_t* ctx);
static int make_connections(spctx_t* ctx, int client);
static int read_server_response(spctx_t* ctx);
static int parse_config_file(const char* configfile);
static char* parse_address(char* line);
static const char* get_successful_rsp(const char* line, int* cont);
static void do_server_noop(spctx_t* ctx);

/* Used externally in some cases */
int sp_parse_option(const char* name, const char* option);

/* ----------------------------------------------------------------------------------
 *  BASIC RUN FUNCTIONALITY 
 */

void sp_init(const char* name)
{
    int r;
    
    ASSERT(name);
    
    memset(&g_state, 0, sizeof(g_state));
    
    sp_message(NULL, LOG_DEBUG, "%s (%s)", name, VERSION);    
    
    /* Setup the defaults */
    g_state.debug_level = -1;
    g_state.max_threads = DEFAULT_MAXTHREADS;
    g_state.timeout.tv_sec = DEFAULT_TIMEOUT;
    g_state.keepalives = DEFAULT_KEEPALIVES;
    g_state.directory = _PATH_TMP;
    g_state.name = name;
    
    /* We need the default to parse into a useable form, so we do this: */
    r = sp_parse_option(CFG_LISTENADDR, DEFAULT_SOCKET);
    ASSERT(r == 1);
    
    /* Create the main mutex and condition variable */  
    if(pthread_mutexattr_init(&g_mtxattr) != 0 ||
#ifdef HAVE_ERR_MUTEX
       pthread_mutexattr_settype(&g_mtxattr, MUTEX_TYPE) ||
#endif       
       pthread_mutex_init(&g_mutex, &g_mtxattr) != 0)
        errx(1, "threading problem. can't create mutex or condition var");  
}
    
int sp_run(const char* configfile, const char* pidfile, int dbg_level)
{
    int sock;
    int true = 1;
    
    ASSERT(configfile);
    ASSERT(g_state.name);
    
    if(!(dbg_level == -1 || dbg_level <= LOG_DEBUG))
        errx(2, "invalid debug log level (must be between 1 and 4)");  
    g_state.debug_level = dbg_level;
    g_state.pidfile = pidfile;
    
    /* Now parse the configuration file */
    if(parse_config_file(configfile) == -1)
    {
        /* 
         * We used to do a check here before whether it was the default
         * configuration file or not, but we can't do that any longer
         * as it comes from the app. Usually lack of a configuration 
         * file will cause the following checks to fail
         */
         warnx("configuration file not found: %s", configfile);
    }
    
    /* This option has no default, but is required ... */
    if(g_state.outname == NULL && !g_state.transparent)
        errx(2, "no " CFG_OUTADDR " specified.");
        
    /* ... unless we're in transparent proxy mode */
    else if(g_state.outname != NULL && g_state.transparent)
        warnx("the " CFG_OUTADDR " option will be ignored when " CFG_TRANSPARENT " is enabled");

    sp_messagex(NULL, LOG_DEBUG, "starting up (%s)...", VERSION);

    /* Create the socket */
    sock = socket(SANY_TYPE(g_state.listenaddr), SOCK_STREAM, 0);
    if(sock < 0)
        err(1, "couldn't open socket");

    fcntl(sock, F_SETFD, fcntl(sock, F_GETFD, 0) | FD_CLOEXEC);    
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true));

#ifdef LINUX_TRANSPARENT_PROXY
    if (g_state.transparent && g_state.tproxy_in)
        setsockopt(sock, IPPROTO_IP, IP_TRANSPARENT, (void *)&true, sizeof(true));
#endif
    
    /* Unlink the socket file if it exists */
    if(SANY_TYPE(g_state.listenaddr) == AF_UNIX)
        unlink(g_state.listenname);

    if(bind(sock, &SANY_ADDR(g_state.listenaddr), SANY_LEN(g_state.listenaddr)) != 0)
        err(1, "couldn't bind to address: %s", g_state.listenname);

    /* Let 5 connections queue up */
    if(listen(sock, 5) != 0)
    {
        sp_message(NULL, LOG_CRIT, "couldn't listen on socket");
        exit(1);
    }
      	
#ifndef LINUX_TRANSPARENT_PROXY
    /* Drop privileges before daemonizing */
    drop_privileges();
#endif
    
    /* When set to this we daemonize */
    if(g_state.debug_level == -1)
    {
        /* Fork a daemon nicely here */
        if(daemon(0, 0) == -1)
        {
            sp_message(NULL, LOG_ERR, "couldn't run as daemon");
            exit(1);
        }
      
        sp_messagex(NULL, LOG_DEBUG, "running as a daemon");
        g_state.daemonized = 1;

        /* Open the system log */
        //openlog(g_state.name, 0, LOG_MAIL);
    }

    /* Open the system log */
    openlog(g_state.name, 0, LOG_MAIL);

    sp_messagex(NULL, LOG_DEBUG, "created socket: %s", g_state.listenname);

    /* Handle some signals */
    signal(SIGPIPE, SIG_IGN); 
    signal(SIGHUP,  SIG_IGN);
    signal(SIGINT,  on_quit);
    signal(SIGTERM, on_quit);

    siginterrupt(SIGINT, 1);
    siginterrupt(SIGTERM, 1);

    pid_file(1);

    sp_messagex(NULL, LOG_DEBUG, "accepting connections");
    
    connection_loop(sock);

    pid_file(0);

    /* Our listen socket */
    close(sock);
            
    sp_messagex(NULL, LOG_DEBUG, "stopped processing");
    return 0;
}

void sp_quit()
{
    /* The handler sets the flag and this also interrupts io */
    kill(getpid(), SIGTERM);
}

int sp_is_quit()
{
    return g_state.quit ? 1 : 0;
}

void sp_done()
{
    /* Close the mutex */
    pthread_mutex_destroy(&g_mutex);
    pthread_mutexattr_destroy(&g_mtxattr);   
    
    if(g_state._p)
        free(g_state._p);

    memset(&g_state, 0, sizeof(g_state));
}

static void on_quit(int signal)
{
    g_state.quit = 1;
}

static void fix_owner(int fd)
{
    char* t;
    struct passwd* pw;
    uid_t uid;

    if(g_state.user)
    {
        uid = strtol(g_state.user, &t, 10);
        if(!t[0]) /* successful parse */
            pw = getpwuid(uid);
        else  /* must be a name */
            pw = getpwnam(g_state.user);

        if(pw == NULL)            
            errx(1, "couldn't look up user: %s", g_state.user);
       
	sp_messagex(NULL, LOG_DEBUG, "changing ownership of fd %d to (user %s uid %d gid %d)", fd, g_state.user, pw->pw_uid, pw->pw_gid);

	if (fchown(fd, pw->pw_uid, pw->pw_gid) == -1) {
		err(1, "unable to fchown file: %s to user %s (uid %d, gid %d)", g_state.user, pw->pw_uid, pw->pw_gid);
	}
    }
}

static void drop_privileges()
{
    char* t;
    struct passwd* pw;
    uid_t uid;
    
    if(g_state.user)
    {
        if(geteuid() != 0)
        {
            sp_messagex(NULL, LOG_WARNING, "must be started as root to switch to user: %s", g_state.user);
            return;
        }
        
        uid = strtol(g_state.user, &t, 10);
        if(!t[0]) /* successful parse */
            pw = getpwuid(uid);
        else  /* must be a name */
            pw = getpwnam(g_state.user);

        if(pw == NULL)            
            errx(1, "couldn't look up user: %s", g_state.user);
        
        if(setgid(pw->pw_gid) == -1 ||
           setuid(pw->pw_uid) == -1)
            err(1, "unable to switch to user: %s (uid %d, gid %d)", g_state.user, pw->pw_uid, pw->pw_gid);
            
        /* A paranoia check */
        if(setreuid(-1, 0) == 0)
            err(1, "unable to completely drop privileges");
            
        sp_messagex(NULL, LOG_DEBUG, "switched to user %s (uid %d, gid %d)", g_state.user, pw->pw_uid, pw->pw_gid);
    }

    if(geteuid() == 0)
        sp_messagex(NULL, LOG_WARNING, "running as root is NOT recommended");
}
  

static void pid_file(int write)
{
    if(!g_state.pidfile)
        return;
        
    if(write)
    {
        FILE* f = fopen(g_state.pidfile, "w");
        if(f == NULL)
        {
            sp_message(NULL, LOG_ERR, "couldn't open pid file: %s", g_state.pidfile);
        }
        else
        {  
            fprintf(f, "%d\n", (int)getpid());
  
            if(ferror(f))
                sp_message(NULL, LOG_ERR, "couldn't write to pid file: %s", g_state.pidfile);
            if(fclose(f) == EOF)
                sp_message(NULL, LOG_ERR, "couldn't write to pid file: %s", g_state.pidfile);
                
        }
        
        sp_messagex(NULL, LOG_DEBUG, "wrote pid file: %s", g_state.pidfile);
    }
    
    else
    {
        unlink(g_state.pidfile);
        sp_messagex(NULL, LOG_DEBUG, "removed pid file: %s", g_state.pidfile);
    }
} 

static void connection_loop(int sock)
{
    spthread_t* threads = NULL;
    int fd, i, x, r;

    /* Create the thread buffers */
    threads = (spthread_t*)calloc(g_state.max_threads, sizeof(spthread_t));
    if(!threads) 
    {
        sp_messagex(NULL, LOG_CRIT, "out of memory");
        return;
    }

    /* Now loop and accept the connections */
    while(!sp_is_quit())
    {
	struct sockaddr_in peer_addr;
	int addr_len = sizeof(peer_addr);
        fd = accept(sock, &peer_addr, &addr_len);
        sp_messagex(NULL, LOG_DEBUG, "Peer address is %s", inet_ntoa(peer_addr.sin_addr));

        if(fd == -1)
        {
            switch(errno)
            {
            case EINTR:
            case EAGAIN:
                break;

            case ECONNABORTED:
                sp_message(NULL, LOG_ERR, "couldn't accept a connection");
                break;

            default:
                sp_message(NULL, LOG_ERR, "couldn't accept a connection");
                break;          
            };

            if(sp_is_quit())
                break;                

            continue;
        }

        /* Set timeouts on client */
        if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &(g_state.timeout), sizeof(g_state.timeout)) < 0 ||
           setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &(g_state.timeout), sizeof(g_state.timeout)) < 0)
            sp_message(NULL, LOG_DEBUG, "couldn't set timeouts on incoming connection");        

        fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);    

        /* Look for thread and also clean up others */
        for(i = 0; i < g_state.max_threads; i++)
        {
            /* Find a thread to run or clean up old threads */
            if(threads[i].tid != 0)
            {
                sp_lock();
                    x = threads[i].fd;
                sp_unlock();

                if(x == -1)
                {
                    sp_messagex(NULL, LOG_DEBUG, "cleaning up completed thread");
                    pthread_join(threads[i].tid, NULL);
                    threads[i].tid = 0;
                }
#ifdef _DEBUG
                else
                {
                    /* For debugging connection problems: */
                    sp_messagex(NULL, LOG_DEBUG, "active connection thread: %x", (int)threads[i].tid);
                }
#endif                    
            }

            /* Start a new thread if neccessary */
            if(fd != -1 && threads[i].tid == 0)
            {
                threads[i].fd = fd;
                r = pthread_create(&(threads[i].tid), NULL, thread_main, 
                                   (void*)(threads + i));
                if(r != 0)
                {
                    errno = r;
                    sp_message(NULL, LOG_ERR, "couldn't create thread");

                    write(fd, SMTP_STARTFAILED, KL(SMTP_STARTFAILED));
                    shutdown(fd, SHUT_RDWR);
                    close(fd);
                    fd = -1;
                    break;
                }

                sp_messagex(NULL, LOG_DEBUG, "created thread for connection");
                fd = -1;
                break;
            }
        }

        /* Check to make sure we have a thread */
        if(fd != -1)
        {
            sp_messagex(NULL, LOG_ERR, "too many connections open (max %d). sent 554 response", g_state.max_threads);
            write(fd, SMTP_STARTBUSY, KL(SMTP_STARTBUSY));
            shutdown(fd, SHUT_RDWR);
            close(fd);
            fd = -1;
        }
    }

    sp_messagex(NULL, LOG_DEBUG, "waiting for threads to quit");

    /* Quit all threads here */
    for(i = 0; i < g_state.max_threads; i++)
    {
        /* Clean up quit threads */
        if(threads[i].tid != 0)
        {
            if(threads[i].fd != -1)
            {
                sp_lock();
                    fd = threads[i].fd;
                    threads[i].fd = -1;
                sp_unlock();
                
                shutdown(fd, SHUT_RDWR);
                close(fd);
            }
          
            pthread_join(threads[i].tid, NULL);
            threads[i].tid = 0;
        }
    }
    
    free(threads);
}

static spctx_t* init_thread(int fd)
{
    spctx_t* ctx;
    
    ctx = cb_new_context();
    if(ctx)
    {
        memset(ctx, 0, sizeof(*ctx));

        spio_init(&(ctx->server), "SERVER");
        spio_init(&(ctx->client), "CLIENT");
        
        sp_lock();
            /* Assign a unique id to the connection */
            ctx->id = g_unique_id++;
            
            /* We don't care about wraps, but we don't want zero */
            if(g_unique_id == 0)
                g_unique_id++;
        sp_unlock();    
            
        sp_messagex(ctx, LOG_DEBUG, "processing %d on thread %x", fd, (int)pthread_self());
        
        /* Connect to the outgoing server ... */
        if(make_connections(ctx, fd) == -1)
        {
            cb_del_context(ctx);
            ctx = NULL;
        }
    }            
    
    return ctx;
}

static void cleanup_context(spctx_t* ctx)
{
    ASSERT(ctx);

    if(ctx->cachefile)
    {
        fclose(ctx->cachefile);
        ctx->cachefile = NULL;
    }
        
    if(ctx->cachename[0])
    {
        unlink(ctx->cachename);
        ctx->cachename[0] = 0;
    }
    
    if(ctx->recipients)
    {
        free(ctx->recipients);
        ctx->recipients = NULL;
    }
    
    if(ctx->sender)
    {
        free(ctx->sender);
        ctx->sender = NULL;
    }

    if (ctx->helo) 
    { 
	free(ctx->helo);
	ctx->helo = NULL;
    }

    //memset(&(ctx->peeraddr), 0, sizeof(ctx->peeraddr));
    
    ctx->logline[0] = 0;
}


static void done_thread(spctx_t* ctx)
{
    ASSERT(ctx);
     
    spio_disconnect(ctx, &(ctx->client));
    spio_disconnect(ctx, &(ctx->server));
    
    /* Clean up file stuff */
    cleanup_context(ctx);            
    cb_del_context(ctx);
}

static void* thread_main(void* arg)
{
    spthread_t* thread = (spthread_t*)arg;
    spctx_t* ctx = NULL;
    int processing = 0;
    int ret = 0;
    int fd;
    
    ASSERT(thread);

    siginterrupt(SIGINT, 1);
    siginterrupt(SIGTERM, 1);

    sp_lock();
        /* Get the client socket */
        fd = thread->fd;
    sp_unlock();    

    /* Sometimes we get to this point and then quit is noted */    
    if(sp_is_quit() || (ctx = init_thread(fd)) == NULL)
    {
        /* Special case. We don't have a context so clean up descriptor */
        close(fd);

        /* new_context() should have already logged reason */
        RETURN(-1);
    }

#ifdef LINUX_TRANSPARENT_PROXY
#ifndef CONFIG_PROP_TSSDK
    /* Drop privileges now that sockets are open */
    drop_privileges();
#endif
#endif

    /* call the processor */
    processing = 1;
    ret = smtp_passthru(ctx);
    
cleanup:

    if(ctx)
    {
        /* Let the client know about fatal errors */
        if(!processing && ret == -1 && spio_valid(&(ctx->client)))
           spio_write_data(ctx, &(ctx->client), SMTP_STARTFAILED);
    
        done_thread(ctx);
    }
    
    /* mark this as done */
    sp_lock();
        thread->fd = -1;
    sp_unlock();

    return (void*)(ret == 0 ? 0 : 1);
}

static int make_connections(spctx_t* ctx, int client)
{
    struct sockaddr_any peeraddr;
    struct sockaddr_any addr;
    struct sockaddr_any* outaddr;
    char buf[MAXPATHLEN];
    const char* outname;
    
    ASSERT(client != -1);

    /* Setup the incoming connection. This also fills in peeraddr for us */
    spio_attach(ctx, &(ctx->client), client, &peeraddr);
    
    /* fill in the client's src ip for future rating usage */
    memcpy(&(ctx->peeraddr), &(peeraddr), sizeof(peeraddr));

    if (cb_check_client(ctx, &peeraddr) == -1) {
        /* peeraddr is the address of the client */
	spio_write_data(ctx, &(ctx->client), "554: Denied due to TrustedSource (see www.trustedsource.org <http://www.trustedsource.org/> for details)\n");
        return -1;
    }
    sp_messagex(ctx, LOG_INFO, "client connection from %s accepted", inet_ntoa(peeraddr.s.in.sin_addr));

    /* Create the server connection address */
    outaddr = &(g_state.outaddr); 
    outname = g_state.outname;
        
    /* For transparent proxying we have to discover the address to connect to */
    if(g_state.transparent)
    {
        int ret;

        memset(&addr, 0, sizeof(addr));
        SANY_LEN(addr) = sizeof(addr);
        
#ifdef LINUX_TRANSPARENT_PROXY
        if (!g_state.tproxy_in)
            ret = getsockopt(ctx->client.fd, SOL_IP, SO_ORIGINAL_DST, &SANY_ADDR(addr), &SANY_LEN(addr));
        else
#endif
            ret = getsockname(ctx->client.fd, &SANY_ADDR(addr), &SANY_LEN(addr));
        if (ret == -1)
        {
            sp_message(ctx, LOG_ERR, "couldn't get source address for transparent proxying");
            return -1;
        }
        
        /* Check address types */
        if(sock_any_cmp(&addr, &peeraddr, SANY_OPT_NOPORT) == 0)
        {
            sp_messagex(ctx, LOG_ERR, "loop detected in transparent proxying");
            return -1;
        }
        
        outaddr = &addr;
    }
    
    /* No transparent proxy but check for loopback option */
    else        
    {
        if(SANY_TYPE(*outaddr) == AF_INET && 
           outaddr->s.in.sin_addr.s_addr == 0)
        {
            /* Use the incoming IP as the default */
            memcpy(&addr, &(g_state.outaddr), sizeof(addr));
            memcpy(&(addr.s.in.sin_addr), &(peeraddr.s.in.sin_addr), sizeof(addr.s.in.sin_addr));
            outaddr = &addr;
        }
#ifdef HAVE_INET6        
        else if(SANY_TYPE(*outaddr) == AF_INET6 && 
                outaddr->s.in.in6.sin_addr.s_addr == 0)
        {
            /* Use the incoming IP as the default */
            memcpy(&addr, &(g_state.outaddr), sizeof(addr));
            memcpy(&(addr.s.in.sin6_addr), &(peeraddr.s.in.sin6_addr), sizeof(addr.s.in.sin6_addr));
            outaddr = &addr;
        }
#endif
    }        
           
    /* Reparse name if possible */
    if(outaddr != &(g_state.outaddr))
    {
        if(sock_any_ntop(outaddr, buf, MAXPATHLEN, 0) != -1)
            outname = buf;
        else
            outname = "unknown";
    }
    
    /* Connect to the server */
    if(spio_connect(ctx, &(ctx->server), &peeraddr, outaddr, outname) == -1)
        return -1;
        
    return 0;
}

/* ----------------------------------------------------------------------------------
 *  SMTP HANDLING
 */
 
static int smtp_passthru(spctx_t* ctx)
{
    char* t;
    const char* p;
    int r, cont, ret = 0;
    unsigned int mask;
    int neterror = 0;

    int first_rsp = 1;      /* The first 220 response from server to be filtered */
    int filter_host = 0;    /* Next response is 250 hostname, which we change */
  
    /* XCLIENT is for use in access control */
    int xclient_sup = 0;    /* Is XCLIENT supported? */
    int xclient_sent = 0;   /* Have we sent an XCLIENT command? */
        
    ASSERT(spio_valid(&(ctx->client)) &&
           spio_valid(&(ctx->server)));
           
    #define C_LINE  ctx->client.line
    #define S_LINE  ctx->server.line

    while(!sp_is_quit())
    {
        mask = spio_select(ctx, &(ctx->client), &(ctx->server), NULL);
        
        if(mask == ~0)
        {
            neterror = 1;
            RETURN(-1);
		}

        /* Client has data available, read a line and process */
        if(mask & 1)
        {
            if((r = spio_read_line(ctx, &(ctx->client), SPIO_DISCARD)) == -1)
                RETURN(-1);

            /* Client disconnected, we're done */
            if(r == 0)
                RETURN(0);

            /* We don't let clients send really long lines */
            if(LINE_TOO_LONG(r))
            {
                if(spio_write_data(ctx, &(ctx->client), SMTP_TOOLONG) == -1)
                    RETURN(-1);

                continue;
            }
            
            /* Only valid after EHLO or HELO commands */
            filter_host = 0;
            
            /* 
             * At this point we may want to send our XCLIENT. This is a per 
             * connection command. 
             */
            if(xclient_sup && !xclient_sent && g_state.xclient)
            {
                sp_messagex(ctx, LOG_DEBUG, "sending XCLIENT");
                
                if(spio_write_dataf(ctx, &(ctx->server), SMTP_XCLIENT, ctx->client.peername) == -1)
                    RETURN(-1);

                if(read_server_response(ctx) == -1)
                    RETURN(-1);
                
                if(!get_successful_rsp(S_LINE, NULL))
                    sp_messagex(ctx, LOG_WARNING, "server didn't accept XCLIENT");
                    
                xclient_sent = 1;
            }

            /* Handle the DATA section via our AV checker */
            if(is_first_word(C_LINE, DATA_CMD, KL(DATA_CMD)))
            {
                /* Send back the intermediate response to the client */
                if(spio_write_data(ctx, &(ctx->client), SMTP_DATAINTERMED) == -1)
                    RETURN(-1);
                    
		if (g_state.precache > 0) {
			if (sp_precache_data(ctx) < 0) {
				/* something went wrong */
				RETURN(-1);
			}

			if (cb_check_precache(ctx) == -1) {
				/* return 0 here so that we don't
				 * bounce it a higher level */
				RETURN(0);
			}
		}

                /* 
                 * Now go into avcheck mode. This also handles the eventual
                 * sending of the data to the server, making the av check
                 * transparent
		 *
		 * Unless we're in passthrough mode - then we go
		 * straight to sp_done_data which feeds the client connection
		 * through to the internal server
                 */
		if (g_state.passthrough) {
			if (sp_done_data(ctx) == -1) {
				RETURN(-1);
			}
		} else {
			if(cb_check_data(ctx) == -1)
			    RETURN(-1);
		}

                /* Print the log out for this email */
                sp_messagex(ctx, LOG_INFO, "%s", ctx->logline);
                    
                /* Done with that email */
                cleanup_context(ctx);

                /* Command handled */
                continue;
            }
                
            /*
             * We need our response to HELO and EHLO to be modified in order 
             * to prevent complaints about mail loops
             */
            else if(is_first_word(C_LINE, EHLO_CMD, KL(EHLO_CMD)))
            {
                /* EHLO can have multline responses so we set a flag */
                filter_host = 1;
		
		/* Can't save the helo C_LINE here as we clean the context
		 * after the servers EHLO response */
            }
            
            /* 
             * We always support XCLIENT on a HELO type connection. We do this
             * for security reasons, so that a client can't get around filtering
             * by backing up one on the protocol.
             */                
            else if(is_first_word(C_LINE, HELO_CMD, KL(HELO_CMD)))
            {
                sp_messagex(ctx, LOG_DEBUG, "XCLIENT support assumed");
                xclient_sup = 1;
                
                /* Filter host as with EHLO above */
                filter_host = 1;

		/* Can't save the helo C_LINE here as we clean the context
		 * after the servers EHLO response */
            }
            
            /* 
             * We don't like these commands. Filter them out. We should have
             * filtered out their service extensions earlier in the EHLO response.
             * This is just for errant clients.
             */
            else if(is_first_word(C_LINE, STARTTLS_CMD, KL(STARTTLS_CMD)) ||
                    is_first_word(C_LINE, BDAT_CMD, KL(BDAT_CMD)))
            {
                sp_messagex(ctx, LOG_DEBUG, "ESMTP feature not supported");
                
                if(spio_write_data(ctx, &(ctx->client), SMTP_NOTSUPP) == -1)
                    RETURN(-1);
                    
                /* Command handled */
                continue;
            }
                        
            /* 
             * For security reasons we're not about to forward any XCLIENTs
             * from our client through. This could lead to a client using our 
             * privileged IP address to change an audit trail or relay etc...
             */
            else if(is_first_word(C_LINE, XCLIENT_CMD, KL(XCLIENT_CMD)))
            {
                sp_messagex(ctx, LOG_WARNING, "client attempted use of privileged XCLIENT feature");
                
                if(spio_write_data(ctx, &(ctx->client), SMTP_NOTAUTH) == -1)
                    RETURN(-1);
                    
                /* Command handled */
                continue;
            }
            
            /* All other commands just get passed through to server */
            if(spio_write_data(ctx, &(ctx->server), C_LINE) == -1)
                RETURN(-1);

            continue;
        }

        /* Server has data available, read a line and forward */
        if(mask & 2)
        {
            if((r = spio_read_line(ctx, &(ctx->server), SPIO_DISCARD)) == -1)
                RETURN(-1);

            if(r == 0)
                RETURN(0);

            if(LINE_TOO_LONG(r))
                sp_messagex(ctx, LOG_WARNING, "SMTP response line too long. discarded extra");

            /* 
             * We intercept the first response we get from the server.
             * This allows us to change header so that it doesn't look
             * to the client server that we're in a wierd loop. 
             * 
             * In different situations using the local hostname or 
             * 'localhost' don't work because the receiving mail server
             * expects one of those to be its own name. We use 'clamsmtp'
             * instead. No properly configured server would have this 
             * as their domain name, and RFC 2821 allows us to use 
             * an arbitrary but identifying string.
             */
            if(first_rsp)
            {
                first_rsp = 0;

                if(is_first_word(S_LINE, START_RSP, KL(START_RSP)))
                {
                    char *banner;
                    int allocated;

                    sp_messagex(ctx, LOG_DEBUG, "intercepting initial response");
                    if (g_state.banner && 
                        (banner = malloc(strlen(BANNER_PREFIX) + strlen(g_state.banner) + strlen(CRLF) + 1))) {
                        strcpy(banner, BANNER_PREFIX);
                        strcat(banner, g_state.banner);
                        strcat(banner, CRLF);
                        allocated = 1;
                    } else {
                        sp_messagex(ctx, LOG_DEBUG, "malloc() failed for banner");
                        banner = SMTP_BANNER;
                        allocated = 0;
                    }
                        
                    if(spio_write_data(ctx, &(ctx->client), banner) == -1) {
                        if (allocated) free(banner);
                        RETURN(-1);
                    }

                    if (allocated) free(banner);

                    /* Command handled */
                    continue;
                }
            }

            if((p = get_successful_rsp(S_LINE, &cont)) != NULL)
            {            
                /* 
                 * Certain mail servers (Postfix 1.x in particular) do a loop check 
                 * on the 250 response after a EHLO or HELO. This is where we
                 * filter that to prevent loopback errors.
                 */
                if(filter_host)
                {
                    char *banner;
                    int allocated;

                    /* Can have multi-line responses, and we want to be 
                     * sure to only replace the first one. */
                    filter_host = 0;
                
                    sp_messagex(ctx, LOG_DEBUG, "intercepting host response");

                    if (g_state.banner && 
                        (banner = malloc(strlen(cont ? EHLO_PREFIX : HELO_PREFIX) + strlen(g_state.banner) + strlen(CRLF) + 1))) {
                        strcpy(banner, cont ? EHLO_PREFIX : HELO_PREFIX);
                        strcat(banner, g_state.banner);
                        strcat(banner, CRLF);
                        allocated = 1;
                    } else {
                        sp_messagex(ctx, LOG_DEBUG, "malloc() failed for banner");
                        banner = cont ? SMTP_EHLO_RSP : SMTP_HELO_RSP;
                        allocated = 0;
                    }
                        
                    if(spio_write_data(ctx, &(ctx->client), banner) == -1) {
                        if (allocated) free(banner);
                        RETURN(-1);      
                    }

                    if (allocated) free(banner);

                    /* A new email so cleanup */
                    cleanup_context(ctx);

		    /* Now we can save the HELO line from the client */
		    ctx->helo = strndup(C_LINE, SP_LINE_LENGTH);
                        
                    continue;
                }
                              
                /* 
                 * Filter out any EHLO responses that we can't or don't want
                 * to support. For example pipelining or TLS. 
                 */
                if(is_first_word(C_LINE, EHLO_CMD, KL(EHLO_CMD)))
                {
                    /* 
                     * On ESMTP connections we let the server tell us whether it
                     * wants XCLIENTs or not. (In contrast to old SMTP above).
                     */
                    if(is_first_word(p, ESMTP_XCLIENT, KL(ESMTP_XCLIENT)))
                    {
                        sp_messagex(ctx, LOG_DEBUG, "XCLIENT supported");
                        xclient_sup = 1;
                    }
                    
                    if(is_first_word(p, ESMTP_PIPELINE, KL(ESMTP_PIPELINE)) ||
                       is_first_word(p, ESMTP_TLS, KL(ESMTP_TLS)) ||
                       is_first_word(p, ESMTP_CHUNK, KL(ESMTP_CHUNK)) ||
                       is_first_word(p, ESMTP_BINARY, KL(ESMTP_BINARY)) ||
                       is_first_word(p, ESMTP_CHECK, KL(ESMTP_CHECK)) ||
                       is_first_word(p, ESMTP_XCLIENT, KL(ESMTP_XCLIENT)))
                    {
                        sp_messagex(ctx, LOG_DEBUG, "filtered ESMTP feature: %s", trim_space((char*)p));
                        
                        /* 
                         * If this is the last line in the EHLO response we need
                         * to replace it with something else 
                         */
                        if(!cont)
                        {
                            if(spio_write_data(ctx, &(ctx->client), SMTP_FEAT_RSP) == -1)
                                RETURN(-1);                            
                        }
                        
                        continue;
                    }
                }

                /* MAIL FROM */
                if((r = check_first_word(C_LINE, FROM_CMD, KL(FROM_CMD), SMTP_DELIMS)) > 0)
                {
                    t = parse_address(C_LINE + r);
                    sp_add_log(ctx, "from=", t);

                    /* Make note of the sender for later */
                    ctx->sender = (char*)reallocf(ctx->sender, strlen(t) + 1);
                    if(ctx->sender)
                        strcpy(ctx->sender, t);
                }
                
                /* RCPT TO */
                else if((r = check_first_word(C_LINE, TO_CMD, KL(TO_CMD), SMTP_DELIMS)) > 0)
                {
                    t = parse_address(C_LINE + r);
                    sp_add_log(ctx, "to=", t);
                    
                    /* Make note of the recipient for later */
                    r = ctx->recipients ? strlen(ctx->recipients) : 0;
                    ctx->recipients = (char*)reallocf(ctx->recipients, r + strlen(t) + 2);
                    if(ctx->recipients)
                    {
                        /* Recipients are separated by lines */
                        if(r != 0)
                            strcat(ctx->recipients, "\n");
                        else
                            ctx->recipients[0] = 0;
                            
                        strcat(ctx->recipients, t);
                    }
                }
                
                /* RSET */
                else if(is_first_word(C_LINE, RSET_CMD, KL(RSET_CMD)))
                {
                    cleanup_context(ctx);
                }
            }
                            
            if(spio_write_data(ctx, &(ctx->client), S_LINE) == -1)
                RETURN(-1);

            continue;
        }        
    }
        
cleanup:

    if(!neterror && ret == -1 && spio_valid(&(ctx->client)))
       spio_write_data(ctx, &(ctx->client), SMTP_FAILED);
        
    return ret;
}

/* -----------------------------------------------------------------------------
 *  SMTP PASSTHRU FUNCTIONS FOR DATA CHECK
 */

static char* parse_address(char* line)
{
    char* t;
    line = trim_start(line);
    
    /*
     * We parse out emails in the form of <blah@blah.com> 
     * as well as accept other addresses.
     */
    if(line[0] == '<')
    {
        if((t = strchr(line, '>')) != NULL)
        {   
            *t = 0;
            line++;
            return line;
        }
    }
    
    return trim_end(line);
}

static const char* get_successful_rsp(const char* line, int* cont)
{
    /*
     * We check for both '250 xxx' type replies
     * and the continued response '250-xxxx' type
     */
     
    line = trim_start(line);
    
    if(line[0] == '2' && isdigit(line[1]) && isdigit(line[2]) &&
       (line[3] == ' ' || line[3] == '-'))
    {
        if(cont)
            *cont = (line[3] == '-');
        return line + 4;
    }
   
    return NULL;
}

void sp_add_log(spctx_t* ctx, char* prefix, char* line)
{
    char* t = ctx->logline;
    int l = strlen(t);
    int x;
    
    ASSERT(l <= SP_LOG_LINE_LEN);

    /* Add up necessary lengths */
    x = 2 + strlen(prefix) + strlen(line) + 1;

    if(l + x >= SP_LOG_LINE_LEN)
        l = SP_LOG_LINE_LEN - x;
        
    t += l;
    l = SP_LOG_LINE_LEN - l;    
    
    *t = 0;
    
    if(ctx->logline[0] != 0)
        strlcat(t, ", ", l);
        
    strlcat(t, prefix, l);
    
    /* Skip initial white space */
    line = trim_start(line);
        
    strlcat(t, line, l);
    
    /* Skip later white space */
    trim_end(t);    
}

int sp_read_data(spctx_t* ctx, const char** data)
{
    int r;
    
    ASSERT(ctx);
    ASSERT(data);
    
    *data = NULL;
    
    switch(r = spio_read_line(ctx, &(ctx->client), SPIO_QUIET))
    {
    case 0:
        sp_messagex(ctx, LOG_ERR, "unexpected end of data from client");
        return -1;
    case -1:
        /* Message already printed */
        return -1;
    };
    
    if(g_state.keepalives > 0)
    {
        /* 
         * During this time we're just reading from the client. If we haven't
         * had any interaction with the server recently then send something 
         * to let it know we're still around.
         */
        if((ctx->server.last_action + g_state.keepalives) < time(NULL))
            do_server_noop(ctx);
    }
    
    if(ctx->_crlf && strcmp(ctx->client.line, DATA_END_SIG) == 0)
        return 0;
        
    /* Check if this line ended with a CRLF */
    ctx->_crlf = (strcmp(CRLF, ctx->client.line + (r - KL(CRLF))) == 0);
    *data = ctx->client.line;
    return r;
}

int sp_write_data(spctx_t* ctx, const char* buf, int len)
{
    int r = 0; 

    ASSERT(ctx);
    
    /* When a null buffer close the cache file */
    if(!buf)
    {
        if(ctx->cachefile)
        {          
            if(fclose(ctx->cachefile) == EOF)
            {
                sp_message(ctx, LOG_ERR, "couldn't write to cache file: %s", ctx->cachename);
                r = -1;
            }

            ctx->cachefile = NULL;
        }
        
        return r;
    }
    
    /* Make sure we have a file open */
    if(!ctx->cachefile)
    {
        int tfd;

        /* Make sure afore mentioned file is gone */
        if(ctx->cachename[0])
            unlink(ctx->cachename);
        
        snprintf(ctx->cachename, MAXPATHLEN, "%s/%s.XXXXXX", 
                 g_state.directory, g_state.name);
        
        if((tfd = mkstemp(ctx->cachename)) == -1 ||
           (ctx->cachefile = fdopen(tfd, "w")) == NULL)
        {
            if(tfd != -1)
                close(tfd);
                
            sp_message(ctx, LOG_ERR, "couldn't open cache file");
            return -1;
        }

#ifdef CONFIG_PROP_TSSDK
	/* if we're doing TS, then we're running as root
	 * but clam needs to be able to read the file */
	fix_owner(tfd);
#endif

        fcntl(tfd, F_SETFD, fcntl(tfd, F_GETFD, 0) | FD_CLOEXEC);    
        sp_messagex(ctx, LOG_DEBUG, "created cache file: %s", ctx->cachename);
    }
	
    fwrite(buf, 1, len, ctx->cachefile);
    
    if(ferror(ctx->cachefile))
    {
        sp_message(ctx, LOG_ERR, "couldn't write to cache file: %s", ctx->cachename);
        return -1;
    }    

    return len;    
}

int sp_precache_data(spctx_t* ctx)
{
    int r, count = 0;
    const char* data;
    
    if(!ctx->precache) {
        ctx->precache = (char *)calloc(1, g_state.precache + 1);

        sp_messagex(ctx, LOG_DEBUG, "allocating memory for precache %p, size %d", ctx->precache, g_state.precache+1);

        if (!ctx->precache)
        {
            sp_messagex(ctx, LOG_ERR, "out of memory for precache");
            return -1;
        }
    } else {
        /* just to be sure */
        memset(ctx->precache, 0, g_state.precache+1);
    }

    while((r = sp_read_data(ctx, &data)) != 0)
    {
        if(r < 0)
            return -1;  /* Message already printed */

        if ((count + r) > g_state.precache) 
            break;

        memcpy(ctx->precache + count, data, r);
        count += r;
    }

    if (r == 0) {
        ctx->precached_all = 1;

        sp_messagex(ctx, LOG_DEBUG, "saw end of data command in precache");
    } 

    ctx->precached_size = count;

    /* the last line read that didn't fit is still stored within the
     * context as client_line */

    sp_messagex(ctx, LOG_DEBUG, "wrote %d bytes to precache", count);
    return count;   
}


int sp_cache_data(spctx_t* ctx)
{
    int r, count = 0;
    const char* data;
    
    /* if we're precaching to memory, write the precache to the 
     * cache file first */
    if (g_state.precache && ctx->precached_size) {

        if((r = sp_write_data(ctx, ctx->precache, ctx->precached_size)) < 0)
            return -1;

        count += r;
        ctx->precached_size = 0;

        /* also need the last line that is stored in the ctx */
        if (!ctx->precached_all) {
            if ((r = sp_write_data(ctx, ctx->client.line, strlen(ctx->client.line))) < 0) {
                return -1;
            }
            count += r;
        } else { 
            /* end the cache */
            if(sp_write_data(ctx, NULL, 0) < 0)
                return -1;
            return count;   
        }
    }

    while((r = sp_read_data(ctx, &data)) != 0)
    {
        if(r < 0)
            return -1;  /* Message already printed */
            
        count += r;
            
        if((r = sp_write_data(ctx, data, r)) < 0)
            return -1;  /* Message already printed */

	if (count >= g_state.precache) {
		cb_check_data(&ctx);
	}
    }
    
    /* End the caching */
    if(sp_write_data(ctx, NULL, 0) < 0)
        return -1;
        
    sp_messagex(ctx, LOG_DEBUG, "wrote %d bytes to cache", count);
    return count;   
}

/* Important: |date| should be at least MAX_DATE_LENGTH long */
static void make_date(spctx_t* ctx, char* date)
{
    size_t date_len;
    struct tm t2;
    time_t t;

    /* Get a basic date like: 'Wed Jun 30 21:49:08 1993' */    
    if(time(&t) == (time_t)-1 || 
       !localtime_r(&t, &t2) || 
       !asctime_r(&t2, date))
    {
        sp_message(ctx, LOG_WARNING, "unable to get date for header");
        date[0] = 0;
        return;
    }
      
    trim_end(date);
    date_len = strlen(date);

    {
#ifdef HAVE_TM_GMTOFF
        time_t timezone = t2.tm_gmtoff;
        const char *tzname[2] = { t2.tm_zone, t2.tm_zone };

        snprintf(date + date_len, MAX_DATE_LENGTH - date_len, " %+03d%02d (%s)", 
                 (int)(timezone / 3600), (int)(timezone % 3600),
                 tzname[t2.tm_isdst ? 1 : 0]);
#else
        /* Apparently Solaris needs this nasty hack.... */
        #define DAY_MIN         (24 * HOUR_MIN)
        #define HOUR_MIN        60
        #define MIN_SEC         60

        struct tm gmt;
        struct tm *lt;
        int off;

        gmt = *gmtime(&t);
        lt = localtime(&t);
        off = (lt->tm_hour - gmt.tm_hour) * HOUR_MIN + lt->tm_min - gmt.tm_min;

        if (lt->tm_year < gmt.tm_year)
            off -= DAY_MIN;
        else if (lt->tm_year > gmt.tm_year)
            off += DAY_MIN;
        else if (lt->tm_yday < gmt.tm_yday)
            off -= DAY_MIN;
        else if (lt->tm_yday > gmt.tm_yday)
            off += DAY_MIN;
        if (lt->tm_sec <= gmt.tm_sec - MIN_SEC)
            off -= 1;
        else if (lt->tm_sec >= gmt.tm_sec + MIN_SEC)
            off += 1;

        snprintf(date + date_len, MAX_DATE_LENGTH - date_len,
                 " %+03d%02d (%s)", (int)(off / HOUR_MIN), (int)(abs(off) % HOUR_MIN),
                 tzname[lt->tm_isdst ? 1 : 0]);
#endif    
    }
    
    /* Break it off just in case */
    date[MAX_DATE_LENGTH - 1] = 0;
}

/* Important: |header| should be a buffer of MAX_HEADER_LENGTH */
static int make_header(spctx_t* ctx, const char* format_str, char* header)
{
    char date[MAX_DATE_LENGTH];
    int remaining, l; 
    const char* f;
    char* p;

    date[0] = 0;
    remaining = MAX_HEADER_LENGTH - 1;
    p = header;
    
    /* Parse the format string and replace special characters with our data */
    for(f = format_str; *f && remaining > 0; f++)
    {
        /* A backslash escapes certain characters */
        if(f[0] == '\\' && f[1] != 0)
        {
            switch(*(++f))
            {
            case 'r':
                *p = '\r';
                break;
            case 'n':
                *p = '\n';
                break;
            case 't':
                *p = '\t';
                break;
            default:
                *p = *f;
                break;
            }
            
            ++p;
            --remaining;
        }
        
        /* 
         * Special symbols:
         *    %i: client's IP
         *    %l: server's IP
         *    %d: date
         */
        else if(f[0] == '%' && f[1] != 0)
        {
            switch(*(++f)) 
            {
            case 'i':
                l = strlen(ctx->client.peername);
                strncpy(p, ctx->client.peername, remaining);
                remaining -= l;
                p += l;
                break;
            case 'l':
                l = strlen(ctx->client.localname);
                strncpy(p, ctx->client.localname, remaining);
                remaining -= l;
                p += l;
                break;
            case 'd':
                if(date[0] == 0)
                    make_date(ctx, date);
                l = strlen(date);
                strncpy(p, date, remaining);
                remaining -= l;
                p += l;
                break;
            case '%':
				*p = '%';            
				++p;
				break;
            default:
                sp_messagex(ctx, LOG_WARNING, "invalid header symbol: %%%c", *f);
                break;
            };			
        }
        
        else
        {
            *(p++) = *f;
            remaining--;
        }
    }
    
    if((p + 1) < (header + MAX_HEADER_LENGTH))
        p[1] = 0;
    header[MAX_HEADER_LENGTH - 1] = 0;
    l = p - header;
    return l >= MAX_HEADER_LENGTH ? MAX_HEADER_LENGTH - 1 : l; 
}

int sp_done_data(spctx_t* ctx)
{
    FILE* file = 0;
    int had_header = 0;
    int ret = 0;
    char buf[SP_LINE_LENGTH];
    char *line = buf;
    char header[MAX_HEADER_LENGTH];
    size_t header_len = 0;
    char *cache_result = NULL;
    int passthrough_result = 0;
    char *precache = NULL;
    int precache_count = 0;

    
    memset(header, 0, sizeof(header));

    if (!g_state.passthrough) {
        /* Open the file */
        ASSERT(ctx->cachename[0]);  /* Must still be around */
        ASSERT(!ctx->cachefile);    /* File must be closed */

        file = fopen(ctx->cachename, "r");
        if(file == NULL)
        {
            sp_message(ctx, LOG_ERR, "couldn't open cache file: %s", ctx->cachename);
            RETURN(-1);
        }
    }
        
    /* Ask the server for permission to send data */
    if(spio_write_data(ctx, &(ctx->server), SMTP_DATA) == -1)
        RETURN(-1);
    
    if(read_server_response(ctx) == -1)
        RETURN(-1);

    /* If server returns an error then tell the client */
    if(!is_first_word(ctx->server.line, DATA_RSP, KL(DATA_RSP)))
    {
        if(spio_write_data(ctx, &(ctx->client), ctx->server.line) == -1)
            RETURN(-1);
            
        sp_messagex(ctx, LOG_DEBUG, "server refused data transfer");
            
        RETURN(0);
    }

    sp_messagex(ctx, LOG_DEBUG, "sending from cache file: %s", ctx->cachename);
    
    if(g_state.header)
        header_len = make_header(ctx, g_state.header, header);

    /* If we have to prepend the header, do it */
    if(header[0] && g_state.header_prepend && !g_state.passthrough)
    {
	    if(spio_write_data_raw(ctx, &(ctx->server), (char*)header, header_len) == -1 ||
	       spio_write_data_raw(ctx, &(ctx->server), CRLF, KL(CRLF)) == -1)
	        RETURN(-1);
	    had_header = 1;
    }

    /* Transfer actual file data */    
    if (g_state.passthrough) {
        if (g_state.precache && ctx->precache) {
            char *eol;

            /* transfer from the precache first */
            precache = ctx->precache;
            eol = (char *)memchr(precache, '\n', ctx->precached_size);

            if (eol - precache > 0) {
                memset(line, 0, SP_LINE_LENGTH);
                memcpy(line, precache, eol - precache + 1);
                precache = eol + 1;
            }
        } else {
            passthrough_result = sp_read_data(ctx, &line);
        }

    } else {
        cache_result = fgets(line, SP_LINE_LENGTH, file); 
    }

    while(cache_result != NULL || passthrough_result > 0 
	|| (g_state.precache && (
		(precache_count < ctx->precached_size) || 
		((precache_count == ctx->precached_size) 
		&& !ctx->precached_all))))
    {
        /* 
         * If the line is <CRLF>.<CRLF> we need to change it so that 
         * it doesn't end the email. We do this by adding a space. 
         * This won't occur much in clamsmtpd, but proxsmtpd might 
         * have filters that accidentally put this in.
         */
        if(strcmp(line, "." CRLF) == 0)
            strncpy(line, ". " CRLF, SP_LINE_LENGTH);
      
        if(header[0] && !had_header)
        {
            /* 
             * The first blank line we see means the headers are done.
             * At this point we add in our virus checked header.
             */
            if(is_blank_line(line))
            {
                if(spio_write_data_raw(ctx, &(ctx->server), (char*)header, header_len) == -1 ||
                   spio_write_data_raw(ctx, &(ctx->server), CRLF, KL(CRLF)) == -1)
                    RETURN(-1);
            
                had_header = 1;
            }
        }
        
        if(spio_write_data_raw(ctx, &(ctx->server), line, strlen(line)) == -1)
            RETURN(-1);

	precache_count += strlen(line);

        /* read the next line */
        if (g_state.passthrough) {
            if (g_state.precache) {
                if (precache_count < ctx->precached_size) {
                    char *eol;

                    eol = (char *)memchr(precache, '\n', ctx->precached_size - precache_count);
                    if (eol - precache > 0) {
                        memset(line, 0, SP_LINE_LENGTH);
                        memcpy(line, precache, eol - precache + 1);
                        precache = eol + 1;
                    }
                } else if (precache_count == ctx->precached_size && !ctx->precached_all) {
                    /* need this to be sure that we check for more data from
                     * the client */
                    passthrough_result = 1;
                    memset(line, 0, SP_LINE_LENGTH);
                    memcpy(line, ctx->client.line, strlen(ctx->client.line));
                } else if (!ctx->precached_all) {
                    passthrough_result = sp_read_data(ctx, &line);
                }
            } else { 
                passthrough_result = sp_read_data(ctx, &line);
            }

        } else {
            cache_result = fgets(line, SP_LINE_LENGTH, file); 
        }
    }
    
    if (!g_state.passthrough) {
        if(ferror(file)) {
            sp_message(ctx, LOG_ERR, "error reading cache file: %s", ctx->cachename);
            RETURN(-1);
        }
    } else {
        if(passthrough_result < 0) {
            /* Client closed connection unexpectedly */
            return -1; /* Message already printed */
        }
    }

    if (spio_write_data(ctx, &(ctx->server), DATA_END_SIG) == -1) {
        /* Tell the client it went wrong */
        spio_write_data(ctx, &(ctx->client), SMTP_FAILED);
        RETURN(-1);
    }

    sp_messagex(ctx, LOG_DEBUG, "sent email data");    
    
    /* Okay read the response from the server and echo it to the client */
    if(read_server_response(ctx) == -1)
        RETURN(-1);
        
    if(spio_write_data(ctx, &(ctx->client), ctx->server.line) == -1)
        RETURN(-1);
        
cleanup:
    
    if(file)
        fclose(file); /* read-only so no error check */
    
    return ret;
}

int sp_fail_data(spctx_t* ctx, const char* smtp_status)
{
    char buf[256 + KL(SMTP_REJPREFIX) + KL(CRLF) + 1];
    char* t = NULL;
    int len, x;
    int pref = 0;
    int crlf = 0; 
    
    if(smtp_status == NULL)
        smtp_status = SMTP_FAILED;
    
    x = strtol(smtp_status, &t, 10);
    len = strlen(smtp_status); 

    /* We need 3 digits and CRLF at the end for a premade SMTP message */
    if(x == 0 || t != smtp_status + 3)
        pref = 1;
    
    /* We need a CRLF at the end */
    if(strcmp(smtp_status + (len - KL(CRLF)), CRLF) != 0)
        crlf = 1;
        
    if(pref || crlf)
    {
        /* Note that we truncate long lines */
        snprintf(buf, sizeof(buf), "%s%.256s%s", pref ? SMTP_REJPREFIX : "", 
                    smtp_status, crlf ? CRLF : "");
        buf[sizeof(buf) - 1] = 0;
        smtp_status = buf;
    }
    
    if(spio_write_data(ctx, &(ctx->client), smtp_status) == -1)
        return -1;
        
    return 0;
}

static int read_server_response(spctx_t* ctx)
{
    int r;
    
    /* Read response line from the server */
    if((r = spio_read_line(ctx, &(ctx->server), SPIO_DISCARD)) == -1)
        return -1;

    if(r == 0)
    {
        sp_messagex(ctx, LOG_ERR, "server disconnected unexpectedly");
        
        /* Tell the client it went wrong */
        spio_write_data(ctx, &(ctx->client), SMTP_FAILED);
        return 0;
    }

    if(LINE_TOO_LONG(r))
        sp_messagex(ctx, LOG_WARNING, "SMTP response line too long. discarded extra");
        
    return 0;
}

static void do_server_noop(spctx_t* ctx)
{
    if(spio_valid(&(ctx->server)))
    {
        if(spio_write_data(ctx, &(ctx->server), SMTP_NOOP) != -1)
            spio_read_line(ctx, &(ctx->server), SPIO_DISCARD);
    }
}
 
void sp_setup_forked(spctx_t* ctx, int file)
{
    /* Signals we've messed with */
    signal(SIGPIPE, SIG_DFL); 
    signal(SIGHUP,  SIG_DFL);
    signal(SIGINT,  SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    siginterrupt(SIGINT, 0);
    siginterrupt(SIGTERM, 0);
    
    if(ctx->sender)
        setenv("SENDER", ctx->sender, 1);
        
    if(ctx->recipients)
        setenv("RECIPIENTS", ctx->recipients, 1);
    
    if(file && ctx->cachename[0])
        setenv("EMAIL", ctx->cachename, 1);

    if(spio_valid(&(ctx->client)))
        setenv("CLIENT", ctx->client.peername, 1);
    
    if(spio_valid(&(ctx->server)))
        setenv("SERVER", ctx->server.peername, 1);
    
    setenv("TMPDIR", g_state.directory, 1);
}


/* ----------------------------------------------------------------------------------
 *  LOGGING
 */
 
const char kMsgDelimiter[] = ": ";
#define MAX_MSGLEN  256

static void vmessage(spctx_t* ctx, int level, int err, 
                     const char* msg, va_list ap)
{
    size_t len;
    char* m;  
    int e = errno;

    if(g_state.daemonized)
    {
        if(level >= LOG_DEBUG)
            return;
    }
    else
    {                   
        if(g_state.debug_level < level)
            return;
    }
       
    ASSERT(msg);

    len = strlen(msg) + 20 + MAX_MSGLEN;
    m = (char*)alloca(len);

    if(m)
    {
        if(ctx)
            snprintf(m, len, "%06X: %s%s", ctx->id, msg, err ? ": " : "");
        else
            snprintf(m, len, "%s%s", msg, err ? ": " : "");
            
        if(err)
        {
            /* strerror_r doesn't want to work for us for some reason
            strerror_r(e, m + strlen(m), MAX_MSGLEN); */
            
            sp_lock();
                strncat(m, strerror(e), len);
            sp_unlock();
        }
            
        m[len - 1] = 0;
        msg = m;
    }    
  
    /* Either to syslog or stderr */
    //if(g_state.daemonized)
        vsyslog(level, msg, ap);
    //else
        vwarnx(msg, ap);  
}

void sp_messagex(spctx_t* ctx, int level, const char* msg, ...)
{
    va_list ap;
    
    va_start(ap, msg);
    vmessage(ctx, level, 0, msg, ap);
    va_end(ap);
}

void sp_message(spctx_t* ctx, int level, const char* msg, ...)
{
    va_list ap;
    
    va_start(ap, msg);
    vmessage(ctx, level, 1, msg, ap);
    va_end(ap);
}


/* -----------------------------------------------------------------------
 * LOCKING
 */
 
void sp_lock()
{
    int r;
  
#ifdef _DEBUG
    int wait = 0;
#endif
  
#ifdef _DEBUG
    r = pthread_mutex_trylock(&g_mutex);
    if(r == EBUSY)
    {
        wait = 1;
        sp_message(NULL, LOG_DEBUG, "thread will block: %d", pthread_self());
        r = pthread_mutex_lock(&g_mutex);
    }

#else
    r = pthread_mutex_lock(&g_mutex);
  
#endif  
  
    if(r != 0)
    {
        errno = r;
        sp_message(NULL, LOG_CRIT, "threading problem. couldn't lock mutex");
    }
  
#ifdef _DEBUG
    else if(wait)
    {
        sp_message(NULL, LOG_DEBUG, "thread unblocked: %d", pthread_self());
    }
#endif    
}
    
void sp_unlock()
{
    int r = pthread_mutex_unlock(&g_mutex);
    if(r != 0)
    {
        errno = r;
        sp_message(NULL, LOG_CRIT, "threading problem. couldn't unlock mutex");
    }
}

/* -----------------------------------------------------------------------------
 * CONFIG FILE
 */
    
int sp_parse_option(const char* name, const char* value)
{
    char* t;
    int ret = 0;
    
    if(strcasecmp(CFG_MAXTHREADS, name) == 0)
    {
        g_state.max_threads = strtol(value, &t, 10);
        if(*t || g_state.max_threads <= 1 || g_state.max_threads >= 1024) 
            errx(2, "invalid setting: " CFG_MAXTHREADS " (must be between 1 and 1024)");
        ret = 1;
    }
        
    else if(strcasecmp(CFG_TIMEOUT, name) == 0)
    {
        g_state.timeout.tv_sec = strtol(value, &t, 10);
        if(*t || g_state.timeout.tv_sec <= 0) 
            errx(2, "invalid setting: " CFG_TIMEOUT);
        ret = 1;
    }
    
    else if(strcasecmp(CFG_KEEPALIVES, name) == 0)
    {
        g_state.keepalives = strtol(value, &t, 10);
        if(*t || g_state.keepalives < 0)
            errx(2, "invalid setting: " CFG_KEEPALIVES);
        ret = 1;
    }
    
    else if(strcasecmp(CFG_XCLIENT, name) == 0)
    {
        if((g_state.xclient = strtob(value)) == -1)
            errx(2, "invalid value for " CFG_XCLIENT);
        ret = 1;
    }

    else if(strcasecmp(CFG_BANNER, name) == 0)
    {
        char *p = trim_start(value);
        if (strlen(p) == 0) {
                g_state.banner = NULL;
        } else {
                g_state.banner = p;
        }
        ret = 1;
    }
        
    else if(strcasecmp(CFG_OUTADDR, name) == 0)
    {
        if(sock_any_pton(value, &(g_state.outaddr), SANY_OPT_DEFPORT(25)) == -1)
            errx(2, "invalid " CFG_OUTADDR " socket name or ip: %s", value);    
        g_state.outname = value;
        ret = 1;
    }
        
    else if(strcasecmp(CFG_LISTENADDR, name) == 0)
    {
        if(sock_any_pton(value, &(g_state.listenaddr), SANY_OPT_DEFANY | SANY_OPT_DEFPORT(DEFAULT_PORT)) == -1)
            errx(2, "invalid " CFG_LISTENADDR " socket name or ip: %s", value);        
        g_state.listenname = value;
        ret = 1;
    }
            
    else if(strcasecmp(CFG_TRANSPARENT, name) == 0)
    {
        if((g_state.transparent = strtob(value)) == -1)
            errx(2, "invalid value for " CFG_TRANSPARENT);            
        ret = 1;
    }

#ifdef LINUX_TRANSPARENT_PROXY
    else if(strcasecmp(CFG_TPROXYIN, name) == 0)
    {
        if((g_state.tproxy_in = strtob(value)) == -1)
            errx(2, "invalid value for " CFG_TPROXYIN);
        ret = 1;
    }

    else if(strcasecmp(CFG_TPROXYOUT, name) == 0)
    {
        if((g_state.tproxy_out = strtob(value)) == -1)
            errx(2, "invalid value for " CFG_TPROXYOUT);
        ret = 1;
    }
#endif

    else if(strcasecmp(CFG_PASSTHROUGH, name) == 0)
    {
        if((g_state.passthrough = strtob(value)) == -1)
            errx(2, "invalid value for " CFG_PASSTHROUGH);            
        ret = 1;
    }

    else if(strcasecmp(CFG_PRECACHE, name) == 0)
    {
        g_state.precache = strtol(value, &t, 10);
        if(*t || g_state.precache < 0) 
            errx(2, "invalid setting: " CFG_PRECACHE " (must not be less than zero)");
        ret = 1;
    }
 
    else if(strcasecmp(CFG_DIRECTORY, name) == 0)
    {
        if(strlen(value) == 0)
            errx(2, "invalid setting: " CFG_DIRECTORY);   
        g_state.directory = value;
        ret = 1;
    }
    
    else if(strcasecmp(CFG_USER, name) == 0)
    {
        if(strlen(value) == 0)
            errx(2, "invalid setting: " CFG_USER);
        g_state.user = value;
        ret = 1;
    }
    
    else if(strcasecmp(CFG_PIDFILE, name) == 0)
    {
        if(g_state.pidfile != NULL)
            sp_messagex(NULL, LOG_WARNING, "ignoring pid file specified on the command line. ");

        if(strlen(value) == 0)
            g_state.pidfile = NULL;
        else
            g_state.pidfile = value;
        ret = 1;
    }

    else if(strcasecmp(CFG_HEADER, name) == 0)
    {
        g_state.header = trim_start(value);
	    if(strlen(g_state.header) == 0)
	        g_state.header = NULL;
	    else if(is_first_word(RCVD_HEADER, g_state.header, KL(RCVD_HEADER)))
	        g_state.header_prepend = 1;
	    ret = 1;
    }
    
    /* Always pass through to program */    
    if(cb_parse_option(name, value) == 1)
        ret = 1;
        
    return ret;
}
    
static int parse_config_file(const char* configfile)
{
    FILE* f = NULL;
    long len;
    char* p;
    char* t;
    char* n;
    
    ASSERT(configfile); 
    ASSERT(!g_state._p);
    
    f = fopen(configfile, "r");
    if(f == NULL)
    {
        /* Soft errors when default config file and not found */
        if((errno == ENOENT || errno == ENOTDIR))
            return -1;
        else
            err(1, "couldn't open config file: %s", configfile);
    }
    
    /* Figure out size */
    if(fseek(f, 0, SEEK_END) == -1 || (len = ftell(f)) == -1 || fseek(f, 0, SEEK_SET) == -1)
        err(1, "couldn't seek config file: %s", configfile);
        
    if((g_state._p = (char*)malloc(len + 2)) == NULL)
        errx(1, "out of memory");

    /* And read in one block */
    if(fread(g_state._p, 1, len, f) != len)
        err(1, "couldn't read config file: %s", configfile);
        
    fclose(f);
    sp_messagex(NULL, LOG_DEBUG, "read config file: %s", configfile); 
    
    /* Double null terminate the data */
    p = g_state._p;
    p[len] =  '\n';
    p[len + 1] = 0;
   
    n = g_state._p;
    
    /* Go through lines and process them */
    while((t = strchr(n, '\n')) != NULL)
    {
        *t = 0;
        p = n; /* Do this before cleaning below */
        n = t + 1;
        
        p = trim_start(p);
        
        /* Comments and empty lines */
        if(*p == 0 || *p == '#')
            continue;
            
        /* Look for the break between name: value */
        t = strchr(p, ':');
        if(t == NULL)
            errx(2, "invalid config line: %s", p);
            
        /* Null terminate and split value part */
        *t = 0;
        t++;
        
        t = trim_space(t);
        p = trim_space(p);
        
        /* Pass it through our options parsers */
        if(sp_parse_option(p, t) == 0)
        
            /* If not recognized then it's invalid */
            errx(2, "invalid config line: %s", p);            
            
        sp_messagex(NULL, LOG_DEBUG, "parsed option: %s: %s", p, t);
    }
    
    return 0;
}        

