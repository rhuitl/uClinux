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
 */ 

/* 
 * select() and stdio are basically mutually exclusive. 
 * Hence all of this code to try to get some buffering 
 * along with select IO multiplexing. 
 */ 
 
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

#include "compat.h"
#include "usuals.h"
#include "sock_any.h"
#include "stringx.h"
#include "sppriv.h"

#define MAX_LOG_LINE    79
#define GET_IO_NAME(io)  ((io)->name ? (io)->name : "???   ")
#define HAS_EXTRA(io)   ((io)->_ln > 0)

static void close_raw(int* fd)
{
    ASSERT(fd);
    shutdown(*fd, SHUT_RDWR);
    close(*fd);
    *fd = -1;
}

static void log_io_data(spctx_t* ctx, spio_t* io, const char* data, int read)
{
    char buf[MAX_LOG_LINE + 1];
    int pos, len;
        
    ASSERT(ctx && io && data);
    
    for(;;)
    {
        data += strspn(data, "\r\n");
        
        if(!*data)
            break;
            
        pos = strcspn(data, "\r\n");

        len = pos < MAX_LOG_LINE ? pos : MAX_LOG_LINE;
        memcpy(buf, data, len);
        buf[len] = 0;

        sp_messagex(ctx, LOG_DEBUG, "%s%s%s", GET_IO_NAME(io), 
            read ? " < " : " > ", buf);
        
        data += pos;
    }
}

void spio_init(spio_t* io, const char* name)
{
    ASSERT(io && name);
    memset(io, 0, sizeof(*io));
    io->name = name;
    io->fd = -1;
}

void spio_attach(spctx_t* ctx, spio_t* io, int fd, struct sockaddr_any* peer)
{
    struct sockaddr_any peeraddr;
    struct sockaddr_any locaddr;
	
    io->fd = fd;
	
    /* Get the address on which we accepted the connection */
    memset(&locaddr, 0, sizeof(locaddr));
    SANY_LEN(locaddr) = sizeof(locaddr);

    if(getsockname(fd, &SANY_ADDR(locaddr), &SANY_LEN(locaddr)) == -1 ||
	   sock_any_ntop(&locaddr, io->localname, MAXPATHLEN, SANY_OPT_NOPORT) == -1)
    {
		if (errno != EAFNOSUPPORT)
	        sp_message(ctx, LOG_WARNING, "%s: couldn't get socket address", GET_IO_NAME(io));
        strlcpy(io->localname, "UNKNOWN", MAXPATHLEN);
    }
	
    /* If the caller doesn't want the peer then use our own */
    if (peer == NULL)
        peer = &peeraddr;
    
    memset(peer, 0, sizeof(*peer));
    SANY_LEN(*peer) = sizeof(*peer);
        
    if(getpeername(fd, &SANY_ADDR(*peer), &SANY_LEN(*peer)) == -1 ||
       sock_any_ntop(peer, io->peername, MAXPATHLEN, SANY_OPT_NOPORT) == -1)
    {
		if (errno != EAFNOSUPPORT)
	        sp_message(ctx, LOG_WARNING, "%s: couldn't get peer address", GET_IO_NAME(io));
        strlcpy(io->peername, "UNKNOWN", MAXPATHLEN);
    }
    
    /* As a double check */    
    io->line[0] = 0;
    io->_nx = NULL;
    io->_ln = 0;
}

int spio_connect(spctx_t* ctx, spio_t* io, const struct sockaddr_any* src,
                 const struct sockaddr_any* sany, const char* addrname)
{
    int ret = 0;
    int fd;
    
    ASSERT(ctx && io && sany && addrname);
    ASSERT(io->fd == -1);
        
    if((fd = socket(SANY_TYPE(*sany), SOCK_STREAM, 0)) == -1)
        RETURN(-1);

    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &(g_state.timeout), sizeof(g_state.timeout)) == -1 ||
       setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &(g_state.timeout), sizeof(g_state.timeout)) == -1)
        sp_messagex(ctx, LOG_DEBUG, "%s: couldn't set timeouts on connection", GET_IO_NAME(io));

#ifdef LINUX_TRANSPARENT_PROXY
    if (src && g_state.tproxy_out) {
        int true = 1;
        if(setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, (void *)&true, sizeof(true)) == -1)
            sp_message(ctx, LOG_WARNING, "%s: couldn't set transparent mode on connection", GET_IO_NAME(io));
        else if (bind(fd, &SANY_ADDR(*src), SANY_LEN(*src)) == -1)
            sp_message(ctx, LOG_WARNING, "%s: couldn't bind foreign address on connection", GET_IO_NAME(io));
    }
#endif

    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);    
             
    if(connect(fd, &SANY_ADDR(*sany), SANY_LEN(*sany)) == -1)
	{
		close_raw(&fd);
        RETURN(-1);
	}
    
    spio_attach(ctx, io, fd, NULL);
    
cleanup:
    if(ret < 0)
    {
        if(spio_valid(io))
            close_raw(&(io->fd));
            
        sp_message(ctx, LOG_ERR, "%s: couldn't connect to: %s", GET_IO_NAME(io), addrname);
        return -1;
    }

    ASSERT(io->fd != -1);
    sp_messagex(ctx, LOG_DEBUG, "%s connected to: %s", GET_IO_NAME(io), io->peername);
    return 0;
}

void spio_disconnect(spctx_t* ctx, spio_t* io)
{
    ASSERT(ctx && io);
    
    if(spio_valid(io))
    {
        close_raw(&(io->fd));
        sp_messagex(ctx, LOG_DEBUG, "%s connection closed", GET_IO_NAME(io));
    }
}

unsigned int spio_select(spctx_t* ctx, ...)
{
    fd_set mask;
    spio_t* io;
    int ret = 0;
    int have = 0;
    int i = 0;
    va_list ap;
    struct timeval timeout;
     
    ASSERT(ctx);   
    FD_ZERO(&mask);
    
    va_start(ap, ctx);
    
    while((io = va_arg(ap, spio_t*)) != NULL)
    {
        if(spio_valid(io))
        {
            /* We can't handle more than 31 args */
            if(i > (sizeof(int) * 8) - 2)
                break;
            
            /* Check if the buffer has something in it */
            if(HAS_EXTRA(io))
                ret |= (1 << i);
        
            /* Mark for select */
            FD_SET(io->fd, &mask);
            have = 1;
        }
        
        i++;
    }
    
    va_end(ap);
    
    /* If any buffers had something present, then return */
    if(ret != 0)
        return ret;
        
    /* No valid file descriptors */
    if(!have)
        return ~0;
        
    for(;;)
    {
        /* Select can modify the timeout argument so we copy */
        memcpy(&timeout, &(g_state.timeout), sizeof(timeout));
        
        /* Otherwise wait on more data */
        switch(select(FD_SETSIZE, &mask, NULL, NULL, &timeout))
        {
        case 0:
            sp_messagex(ctx, LOG_ERR, "network operation timed out"); 
            return ~0;
            
        case -1:
            if(errno == EINTR)
            {
                if(!sp_is_quit())
                    continue;
            }
            
            else
                sp_message(ctx, LOG_ERR, "couldn't select on sockets");
                
            return ~0;
        };    
        
        break;
    }
    
    /* See what came in */
    i = 0;
    
    va_start(ap, ctx);
    
    while((io = va_arg(ap, spio_t*)) != NULL)
    {
        /* We can't handle more than 31 args */
        if(i > (sizeof(int) * 8) - 2)
            break;
            
        /* We have data on the descriptor, which is an action */
        io->last_action = time(NULL);
        
        /* Check if the buffer has something in it */
        if(FD_ISSET(io->fd, &mask))
            ret |= (1 << i);
        
        i++;
    }
    
    return ret;
}

int read_raw(spctx_t* ctx, spio_t* io, int opts)
{
    int len, x, count;
    char* at;
    char* p;
    
    /*
     * Just a refresher:
     * 
     * _nx: Extra data read on last read.
     * _ln: Length of that extra data.
     * 
     * _nx should never be equal to line when entering this function. 
     * And _ln should always be less than a full buffer.
     */

    count = 0;
    io->line[0] = 0;

    /* Remaining data in the buffer  */
    if(io->_nx && io->_ln > 0)
    {
        ASSERT(!io->_nx || io->_nx > io->line);
        ASSERT(io->_ln < SP_LINE_LENGTH);
        ASSERT(io->_nx + io->_ln <= io->line + SP_LINE_LENGTH);
        
        /* Check for a return in the current buffer */
        if((p = (char*)memchr(io->_nx, '\n', io->_ln)) != NULL)
        {
            /* Move data to front */
            x = (p - io->_nx) + 1;
            ASSERT(x > 0);
            memmove(io->line, io->_nx, x);
            
            /* Null teriminate it */
            io->line[x] = 0;
            
            /* Do maintanence for next time around */
            io->_ln -= x;
            io->_nx += x;
            
            /* A double check on the return value */
            count += x;
            return count;
        }
            
        /* Otherwise move all old data to front */
        memmove(io->line, io->_nx, io->_ln);
        count += io->_ln;

        /* We always leave space for a null terminator */
        len = (SP_LINE_LENGTH - io->_ln) - 1;
        at = io->line + io->_ln;
    }
    
    /* No data at front just read straight in */
    else
    {
        /* We always leave space for a null terminator */
        len = SP_LINE_LENGTH - 1;
        at = io->line;
    }
    
    for(;;)
    {
        /* Read a block of data */
        ASSERT(io->fd != -1);
        x = read(io->fd, at, sizeof(char) * len);
        
        if(x == -1)
        {
            if(errno == EINTR)
            {
                /* When the application is quiting */
                if(sp_is_quit())
                    return -1;
            
                /* For any other signal we go again */
                continue;
            }
        
            if(errno == ECONNRESET) /* Not usually a big deal so supresse the error */
                sp_messagex(ctx, LOG_DEBUG, "%s: connection disconnected by peer", GET_IO_NAME(io));
            else if(errno == EAGAIN)
                sp_messagex(ctx, LOG_WARNING, "%s: network read operation timed out", GET_IO_NAME(io));
            else 
                sp_message(ctx, LOG_ERR, "%s: couldn't read data from socket", GET_IO_NAME(io));

            /* 
             * The basic logic here is that if we've had a fatal error
             * reading from the socket once then we shut it down as it's 
             * no good trying to read from again later.
             */
            close_raw(&(io->fd));
                            
            return -1;      
        }
        
        /* End of data */
        else if(x == 0)
        {
            /* Maintenance for remaining data */
            io->_nx = NULL;
            io->_ln = 0;
            
            return count;
        }

        /* Read data which is a descriptor action */        
        io->last_action = time(NULL);
        
        /* Check for a new line */
        p = (char*)memchr(at, '\n', x);
        if(p != NULL)
        {
            p++;
            count += (p - at);
            
            /* Insert the null terminator */
            len = x - (p - at);
            memmove(p + 1, p, len);
            *p = 0;
            
            /* Do maintenence for remaining data */
            io->_nx = p + 1;
            io->_ln = len;

            return count;            
        }
        
        /* Move the buffer pointer along */
        at += x;
        len -= x;
        count += x;

        if(len <= 0)
        {
            /* Keep reading until we hit a new line */
            if(opts & SPIO_DISCARD)
            {
                /* 
                 * K, basically the logic is that we're discarding
                 * data ond the data will be screwed up. So overwriting
                 * some valid data in order to flush the line and 
                 * keep the buffering simple is a price we pay gladly :)
                 */
                 
                ASSERT(128 < SP_LINE_LENGTH);
                at = (io->line + SP_LINE_LENGTH) - 128;
                len = 128;
                
                /* Go for next read */
                continue;
            }
            
            io->_nx = NULL;
            io->_ln = 0;
            
            /* Null terminate */
            io->line[SP_LINE_LENGTH] = 0;
            
            /* A double check on the return value */
            return count;
        }
    }
}      
        
int spio_read_line(spctx_t* ctx, spio_t* io, int opts)
{
    int x, l;
    char* t;
    
    ASSERT(ctx && io);
    
    if(!spio_valid(io))
    {
        sp_messagex(ctx, LOG_WARNING, "%s: tried to read from a closed connection", GET_IO_NAME(io));
        return 0;
    }

    x = read_raw(ctx, io, opts);
    
    if(x > 0)
    {
        if(opts & SPIO_TRIM)
        {
            t = io->line;
                    
            while(*t && isspace(*t))
                t++;
                                        
            /* Bump the entire line down */
            l = t - io->line;
            memmove(io->line, t, (x + 1) - l);
            x -= l;
            
            /* Now the end */
            t = io->line + x;
            
            while(t > io->line && isspace(*(t - 1)))
            {
                *(--t) = 0;
                x--;
            }
        }
        
        if(!(opts & SPIO_QUIET))
            log_io_data(ctx, io, io->line, 1);
    }
        
    return x;
}

int spio_write_data(spctx_t* ctx, spio_t* io, const char* data)
{
    int len = strlen(data);
    ASSERT(ctx && io && data);
        
    if(!spio_valid(io))
    {
        sp_message(ctx, LOG_ERR, "%s: connection closed. can't write data", GET_IO_NAME(io));
        return -1;
    }
    
    log_io_data(ctx, io, data, 0);
    return spio_write_data_raw(ctx, io, (unsigned char*)data, len);
}

int spio_write_dataf(struct spctx* ctx, spio_t* io, const char* fmt, ...)
{
    char buf[SP_LINE_LENGTH];
    va_list ap;
    ASSERT(ctx && io && fmt);

    buf[0] = 0;
    
    va_start(ap, fmt);
    vsnprintf(buf, SP_LINE_LENGTH, fmt, ap);
    va_end(ap);

    buf[SP_LINE_LENGTH - 1] = 0;
    
    return spio_write_data(ctx, io, buf);
}

int spio_write_data_raw(spctx_t* ctx, spio_t* io, unsigned char* buf, int len)
{
    int r;
    
    ASSERT(ctx && io && buf);
    
    if(io->fd == -1)
        return 0;
        
    io->last_action = time(NULL);
    
    while(len > 0)
    {
        r = write(io->fd, buf, len);

        if(r > 0)
        {
            buf += r;
            len -= r;
        }

        else if(r == -1)
        { 
            if(errno == EINTR)
            {
                /* When the application is quiting */
                if(sp_is_quit())
                    return -1;
                    
                /* For any other signal we go again */
                continue;
            }
            
            /* 
             * The basic logic here is that if we've had a fatal error
             * writing to the socket once then we shut it down as it's 
             * no good trying to write to it again later.
             */
            close_raw(&(io->fd));
            
            if(errno == EAGAIN)
                sp_messagex(ctx, LOG_WARNING, "%s: network write operation timed out", GET_IO_NAME(io));
            else 
                sp_message(ctx, LOG_ERR, "%s: couldn't write data to socket", GET_IO_NAME(io));
                
            return -1;
        }
    }

    return 0;  
}

void spio_read_junk(spctx_t* ctx, spio_t* io)
{
    char buf[16];
    const char* t;
    int said = 0;
    int l;
    
    ASSERT(ctx);
    ASSERT(io);
    
    /* Truncate any data in buffer */
    io->_ln = 0;    
    io->_nx = 0;
    
    if(!spio_valid(io))
        return;
  
    /* Make it non blocking */
    fcntl(io->fd, F_SETFL, fcntl(io->fd, F_GETFL, 0) | O_NONBLOCK);
  
    for(;;)
    {
        l = read(io->fd, buf, sizeof(buf) - 1);
        if(l <= 0)
            break;

        io->last_action = time(NULL);
      
        buf[l] = 0;
        t = trim_start(buf);
        
        if(!said && *t)
        {
            sp_messagex(ctx, LOG_DEBUG, "%s: received junk data from daemon", GET_IO_NAME(io));
            said = 1;
        }
    }

    fcntl(io->fd, F_SETFL, fcntl(io->fd, F_GETFL, 0) & ~O_NONBLOCK);
}
