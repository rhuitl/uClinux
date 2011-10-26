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

#ifndef __SMTPPASS_H__
#define __SMTPPASS_H__

/* Forward declarations */
struct sockaddr_any;
struct spctx;

/* -----------------------------------------------------------------------------
 * BUFFERED MULTIPLEXING IO
 * 
 * This isn't meant to be a replacement library for all sorts of IO
 * only things that are currently used go here. 
 */

/* 
 * A generous maximum line length. It needs to be longer than 
 * a full path on this system can be, because we pass the file
 * name to clamd.
 */
 
#if 2000 > MAXPATHLEN
    #define SP_LINE_LENGTH 2000
#else
    #define SP_LINE_LENGTH (MAXPATHLEN + 128)
#endif

typedef struct spio
{
    int fd;                             /* The file descriptor wrapped */
    const char* name;                   /* The name for logging */
    time_t last_action;                 /* Time of last action on descriptor */
    char peername[MAXPATHLEN];          /* Name of the peer on other side of socket */
    char localname[MAXPATHLEN];         /* Address where we accepted the connection */
    
    /* Internal use only */
    char line[SP_LINE_LENGTH];  
    char* _nx;
    size_t _ln;                         
}
spio_t;

#define spio_valid(io)      ((io)->fd != -1)

/* Setup the io structure (allocated elsewhere) */
void spio_init(spio_t* io, const char* name);

/* Attach an open descriptor to a socket, optionally returning the peer */
void spio_attach(struct spctx* ctx, spio_t* io, int fd, struct sockaddr_any* peer);

/* Connect and disconnect from sockets */
int  spio_connect(struct spctx* ctx, spio_t* io, const struct sockaddr_any* src, const struct sockaddr_any* sany, const char* addrname);
void spio_disconnect(struct spctx* ctx, spio_t* io);

#define SPIO_TRIM           0x00000001
#define SPIO_DISCARD        0x00000002
#define SPIO_QUIET          0x00000004

/* Read a line from a socket. Use options above. Line 
 * will be found in io->line */
int spio_read_line(struct spctx* ctx, spio_t* io, int opts);

/* Write data to socket (must supply line endings if needed). 
 * Guaranteed to accept all data or fail. */
int spio_write_data(struct spctx* ctx, spio_t* io, const char* data);
int spio_write_dataf(struct spctx* ctx, spio_t* io, const char* fmt, ...);
int spio_write_data_raw(struct spctx* ctx, spio_t* io, unsigned char* buf, int len);

/* Empty the given socket */
void spio_read_junk(struct spctx* sp, spio_t* io);
    
/* Pass up to 31 spio_t*, followed by NULL. Returns bitmap of ready for reading */
unsigned int  spio_select(struct spctx* ctx, ...);


/* -----------------------------------------------------------------------------
 * SMTP PASS THROUGH FUNCTIONALITY
 */
 
/* Log lines have to be under roughly 900 chars otherwise 
 * they get truncated by syslog. */
#define SP_LOG_LINE_LEN  768

typedef struct spctx
{ 
    unsigned int id;                /* Identifier for the connection */

    spio_t client;                  /* Connection to client */
    spio_t server;                  /* Connection to server */

    FILE* cachefile;                /* The file handle for the cached file */
    char cachename[MAXPATHLEN];     /* The name of the file that we cache into */
    char logline[SP_LOG_LINE_LEN];  /* Log line */  

    char* sender;                   /* The email of the sender */
    char* recipients;               /* The email of the recipients */
    char* helo;		            /* The clients initial HELO line */
    struct sockaddr_any peeraddr;   /* The clients src ip */
    char *precache;		    /* Precache buffer for message reputation */
    int precached_size;             /* Amount of data in the precache */
    int precached_all;		    /* Did we see the entire message */

    int _crlf;                      /* Private data */
}
spctx_t;


/*
 * Sends the first X bytes from the client into an in-memory
 * precache.
 * Data is then available in spctx->precache for use
 * And sets a flag, spctx->precached_all if we saw the end of the DATA
 * command while filling this precache
 */
int sp_precache_data(spctx_t *ctx);

/* 
 * sp_init initializes the SMTP Pass-Through functionality 
 * The name passed is the name of the app 
 */
void sp_init(const char* name);

/*
 * This starts up the smtp pass thru program. It will call
 * the cb_* functions as appropriate.
 */
int sp_run(const char* configfile, const char* pidfile, int dbg_level);

/* 
 * Mark the application as shutting down. 
 * A signal will interupt most IO.
 */
void sp_quit();

/*
 * Check if the application has been marked to quit.
 * Useful for checking after interupted IO.
 */
int sp_is_quit();
            
/* 
 * Called to cleanup SMTP Pass-Through functionality just
 * before the application quits.
 */
void sp_done();

/* 
 * clamsmtpd used to accept command line args. In order to 
 * process those args it needs to send the values to the 
 * config file routines. This is how it does that.
 */
#ifdef SP_LEGACY_OPTIONS
int sp_parse_option(const char* name, const char* option);
#endif


/* 
 * The following functions are to be called from within 
 * the spc_check_data function.
 */
 
/* 
 * Adds a piece of info to the log line 
 */
void sp_add_log(spctx_t* ctx, char* prefix, char* line);

/* 
 * Reads a line of DATA from client. Or less than a line if 
 * line is longer than LINE_LENGTH. No trimming or anything
 * is done on the read line. This will end automatically
 * when <CRLF>.<CRLF> is detected (in which case 0 will 
 * be returned). The data is returned in data.
 */
int sp_read_data(spctx_t* ctx, const char** data);

/*
 * Writes a line (or piece) of data to a file buffer which is 
 * later sent to the client using sp_done_data. Calling it with
 * a NULL buffer closes the cache file. Guaranteed to accept
 * all data given to it or fail.
 */
int sp_write_data(spctx_t* ctx, const char* buf, int buflen);

/*
 * Sends all DATA from the client into the cache. The cache
 * file is then available (in spctx_t->cachename) for use.
 */
int sp_cache_data(spctx_t* ctx);

/* 
 * Sends the data in file buffer off to server. This is 
 * completes a successful mail transfer. 
 */
int sp_done_data(spctx_t* ctx);

/* 
 * Fails the data, deletes any temp data, and sends given 
 * status to client or if NULL then SMTP_DATAFAILED 
 */
int sp_fail_data(spctx_t* ctx, const char* smtp_status);

/*
 * Setup the environment with context info. This is useful
 * if you're going to fork another process. Be sure to exec
 * soon after to prevent the strings from going out of scope. 
 */
void sp_setup_forked(spctx_t* ctx, int file);

/* 
 * Log a message. levels are syslog levels. Syntax is just
 * like printf etc.. Can specify a ctx of NULL in which case
 * no connection prefix is prepended.
 */
void sp_message(spctx_t* ctx, int level, const char* msg, ...);
void sp_messagex(spctx_t* ctx, int level, const char* msg, ...);

/*
 * Lock or unlock the main mutex around thread common 
 * functionality.
 */
void sp_lock();
void sp_unlock();


/* -----------------------------------------------------------------------------
 * CALLBACKS IMPLMEMENTED BY PROGRAM
 */

/* 
 * The following functions create and destroy contexts for a new 
 * thread. Perform initialization in there and return a spctx
 * structure for the thread to use. Return NULL failed. Be sure 
 * to log message.
 */
extern spctx_t* cb_new_context();
extern void cb_del_context(spctx_t* ctx);

/* 
 * Called when the data section of an email is being transferred.
 * Once inside this function you can transfer files using 
 * sp_read_data, sp_write_data.
 * 
 * After scanning or figuring out the status call either 
 * sp_done_data or sp_fail_data. Most failures should be handled
 * internally using sp_fail_data, unless it's an out of memory
 * condition, or sp_fail_data failed.
 */
extern int cb_check_data(spctx_t* ctx);

/* 
 * Parse options from the config file. The memory for these
 * options will stay around until sp_done is called. Return 0
 * for unrecognized options, 1 for recognized, and quit the 
 * program for invalid.
 */
extern int cb_parse_option(const char* name, const char* value);

/*
 * Called just after the incoming connection is received.
 * 
 * Return -1 to close the connection and not allow the client 
 * connection to be established
 */
extern int cb_check_client(spctx_t* ctx, struct sockaddr_any* peeraddr);

#endif /* __SMTPPASS_H__ */
