
/*
 * $Id$
 * 
 * DEBUG: section 81    Internet Content Adaptation Protocol (ICAP) Client OPTIONS
 * AUTHOR: Ralf Horstmann
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"

/*************************************************************/

/*
 * network related functions for OPTIONS request
 */
static void icapOptStart(void *data);
static void icapOptTimeout(int fd, void *data);
static void icapOptConnectDone(int server_fd, int status, void *data);
static void icapOptWriteComplete(int fd, char *bufnotused, size_t size, int errflag, void *data);
static void icapOptReadReply(int fd, void *data);

/*
 * reply parsing functions
 */
static int icapOptParseReply(icap_service * s, IcapOptData * i);
static void icapOptParseEntry(icap_service * s, const char *blk_start, const char *blk_end);
static int icapIsolateLine(const char **parse_start, const char **blk_start, const char **blk_end);

/*
 * helper functions
 */
static void icapOptDataInit(IcapOptData * i);
static void icapOptDataFree(IcapOptData * i);

/*************************************************************/

#define TIMEOUT 10

void
icapOptInit()
{
    icap_service *s;

    /* iterate over configured services */
    s = Config.icapcfg.service_head;
    while (s) {
	eventAdd("icapOptStart", icapOptStart, s, 5.0, 1);
	s = s->next;
    }
}

void
icapOptShutdown()
{
    icap_service *s;

    s = Config.icapcfg.service_head;
    while (s) {
	if (eventFind(icapOptStart, s)) {
	    eventDelete(icapOptStart, s);
	}
	s = s->next;
    }
}

/*
 * mark a service as unreachable
 */
void
icapOptSetUnreachable(icap_service * s)
{
    s->unreachable = 1;
    debug(81, 5) ("icapOptSetUnreachable: got called for %s\n", s->uri);
    /*
     * if there is an options request scheduled, delete it and add
     * it again to reset the time to the default check_interval.
     */
    if (eventFind(icapOptStart, s)) {
	eventDelete(icapOptStart, s);
	eventAdd("icapOptStart", icapOptStart, s, Config.icapcfg.check_interval, 1);
    }
}

static void
icapOptStart(void *data)
{
    icap_service *s = data;
    int fd;
    int ctimeout = TIMEOUT;
    const char *host = s->hostname;
    unsigned short port = s->port;
    debug(81, 3) ("icapOptStart: starting OPTIONS request for %s (%s)\n", s->name, s->uri);
    fd = comm_open(SOCK_STREAM,
	0,
	getOutgoingAddr(NULL),
	0,
	COMM_NONBLOCKING,
	"ICAP OPTIONS connection");
    if (fd < 0) {
	debug(81, 4) ("icapConnectStart: %s\n", xstrerror());
	eventAdd("icapOptStart", icapOptStart, s, Config.icapcfg.check_interval, 1);
	return;
    }
    assert(s->opt == NULL);	/* if not null, another options request might be running, which should not happen */
    s->opt = memAllocate(MEM_ICAP_OPT_DATA);
    icapOptDataInit(s->opt);
    cbdataLock(s);
    commSetTimeout(fd, ctimeout, icapOptTimeout, s);
    commConnectStart(fd, host, port, icapOptConnectDone, s);
}

static void
icapOptTimeout(int fd, void *data)
{
    icap_service *s = data;
    IcapOptData *i = s->opt;
    int valid;

    debug(81, 4) ("icapOptConnectTimeout: fd=%d, service=%s\n", fd, s->uri);

    comm_close(fd);
    valid = cbdataValid(s);
    cbdataUnlock(s);
    if (!valid) {
	icapOptDataFree(i);
	s->opt = NULL;
	return;
    }
    /* try again later */
    icapOptDataFree(i);
    s->opt = NULL;
    s->unreachable = 1;
    debug(81, 3) ("icapOptConnectTimeout: unreachable=1, service=%s\n", s->uri);
    eventAdd("icapOptStart", icapOptStart, s, Config.icapcfg.check_interval, 1);

}

static void
icapOptConnectDone(int server_fd, int status, void *data)
{
    icap_service *s = data;
    IcapOptData *i = s->opt;
    MemBuf request;
    int valid;

    valid = cbdataValid(s);
    cbdataUnlock(s);
    if (!valid) {
	comm_close(server_fd);
	icapOptDataFree(i);
	s->opt = NULL;
	return;
    }
    if (status != COMM_OK) {
	debug(81, 3) ("icapOptConnectDone: unreachable=1, service=%s\n", s->uri);
	comm_close(server_fd);
	icapOptDataFree(i);
	s->opt = NULL;
	s->unreachable = 1;
	eventAdd("icapOptStart", icapOptStart, s, Config.icapcfg.check_interval, 1);
	return;
    }
    debug(81, 3) ("icapOptConnectDone: Connection ok. Sending Options request for %s\n", s->name);
    memBufDefInit(&request);
    memBufPrintf(&request, "OPTIONS %s ICAP/1.0\r\n", s->uri);
    memBufPrintf(&request, "Host: %s\r\n", s->hostname);
    memBufPrintf(&request, "Connection: close\r\n");
    memBufPrintf(&request, "User-Agent: ICAP-Client-Squid/1.2\r\n");
    memBufPrintf(&request, "\r\n");
    cbdataLock(s);
    commSetTimeout(server_fd, TIMEOUT, icapOptTimeout, s);
    comm_write_mbuf(server_fd, request, icapOptWriteComplete, s);
}

static void
icapOptWriteComplete(int fd, char *bufnotused, size_t size, int errflag, void *data)
{
    icap_service *s = data;
    IcapOptData *i = s->opt;
    int valid;

    valid = cbdataValid(s);
    cbdataUnlock(s);
    if (!valid) {
	comm_close(fd);
	icapOptDataFree(i);
	s->opt = NULL;
	return;
    }
    debug(81, 5) ("icapOptWriteComplete: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);
    if (size > 0) {
	fd_bytes(fd, size, FD_WRITE);
	kb_incr(&statCounter.icap.all.kbytes_out, size);
    }
    if (errflag) {
	/* cancel this for now */
	debug(81, 3) ("icapOptWriteComplete: unreachable=1, service=%s\n", s->uri);
	icapOptDataFree(i);
	s->opt = NULL;
	s->unreachable = 1;
	eventAdd("icapOptStart", icapOptStart, s, Config.icapcfg.check_interval, 1);
	comm_close(fd);
	return;
    }
    cbdataLock(s);
    commSetSelect(fd, COMM_SELECT_READ, icapOptReadReply, s, 0);
}

static void
icapOptReadReply(int fd, void *data)
{
    icap_service *s = data;
    IcapOptData *i = s->opt;
    int size;
    int len = i->size - i->offset - 1;
    int valid;

    valid = cbdataValid(s);
    cbdataUnlock(s);
    if (!valid) {
	comm_close(fd);
	icapOptDataFree(i);
	s->opt = NULL;
	return;
    }
    if (len == 0) {
	/* Grow the request memory area to accomodate for a large request */
	printf("PANIC: not enough memory\n");
#if 0
	i->buf = memReallocBuf(i->buf, i->size * 2, &i->size);
	debug(81, 2) ("icapoptReadReply: growing reply buffer: offset=%ld size=%ld\n",
	    (long) i->offset, (long) i->size);
	len = i->size - i->offset - 1;
#endif
    }
    size = FD_READ_METHOD(fd, i->buf + i->offset, len);
    i->offset += size;
    debug(81, 3) ("icapOptReadReply: Got %d bytes of data\n", size);
    if (size > 0) {
	/* do some statistics */
	fd_bytes(fd, size, FD_READ);
	kb_incr(&statCounter.icap.all.kbytes_in, size);

	/* 
	 * some icap servers seem to ignore the  "Connection: close" header. so 
	 * after getting the complete option reply we close the connection 
	 * ourself.
	 */
	if ((i->headlen = headersEnd(i->buf, i->offset))) {
	    debug(81, 3) ("icapOptReadReply: EndOfResponse\n");
	    size = 0;
	}
    }
    if (size < 0) {
	debug(81, 3) ("icapOptReadReply: FD %d: read failure: %s.\n", fd, xstrerror());
	debug(81, 3) ("icapOptReadReply: unreachable=1, service=%s.\n", s->uri);
	s->unreachable = 1;
	icapOptDataFree(i);
	s->opt = NULL;
	eventAdd("icapOptStart", icapOptStart, s, Config.icapcfg.check_interval, 1);
	comm_close(fd);
    } else if (size == 0) {
	/* no more data, now we can parse the reply */
	debug(81, 3) ("icapOptReadReply: FD %d: connection closed\n", fd);
	i->buf[i->offset] = '\0';	/* for string functions */
	debug(81, 3) ("icapOptReadReply: unreachable=0, service=%s\n", s->uri);
	if (icapOptParseReply(s, i) && s->options_ttl > 0) {
	    debug(81, 3) ("icapOptReadReply: OPTIONS request successful. scheduling again in %d seconds\n", s->options_ttl);
	    s->unreachable = 0;
	    eventAdd("icapOptStart", icapOptStart, s, s->options_ttl, 1);
	} else {
	    /* use a default ttl */
	    debug(81, 3) ("icapOptReadReply: OPTIONS request not successful. scheduling again in %d seconds\n", Config.icapcfg.check_interval);
	    s->unreachable = 1;
	    eventAdd("icapOptStart", icapOptStart, s, Config.icapcfg.check_interval, 1);
	}
	icapOptDataFree(i);
	s->opt = NULL;
	comm_close(fd);
    } else {
	/* data received */
	/* commSetSelect(fd, Type, handler, client_data, timeout) */
	cbdataLock(s);
	commSetSelect(fd, COMM_SELECT_READ, icapOptReadReply, data, 0);
    }
}

static int
icapIsolateLine(const char **parse_start, const char **blk_start, const char **blk_end)
{
    int slen = strcspn(*parse_start, "\r\n");

    if (!(*parse_start)[slen])	/* no crlf */
	return 0;

    if (slen == 0)		/* empty line */
	return 0;

    *blk_start = *parse_start;
    *blk_end = *blk_start + slen;

    /* set it to the beginning of next line */
    *parse_start = *blk_end;
    while (**parse_start == '\r')	/* CR */
	(*parse_start)++;
    if (**parse_start == '\n')	/* LF */
	(*parse_start)++;
    return 1;
}

/* process a single header entry between blk_start and blk_end */
static void
icapOptParseEntry(icap_service * s, const char *blk_start, const char *blk_end)
{
    const char *name_end = strchr(blk_start, ':');
    const int name_len = name_end ? name_end - blk_start : 0;
    const char *value_start = blk_start + name_len + 1;		/* skip ':' */
    int value_len;
    int new;

    if (!name_len || name_end > blk_end) {
	debug(81, 5) ("icapOptParseEntry: strange header. skipping\n");
	return;
    }
    if (name_len > 65536) {
	debug(81, 5) ("icapOptParseEntry: unusual long header item. skipping.\n");
	return;
    }
    while (xisspace(*value_start) && value_start < blk_end) {
	value_start++;
    }
    if (value_start >= blk_end) {
	debug(81, 5) ("icapOptParseEntry: no value found\n");
	return;
    }
    value_len = blk_end - value_start;


    /* extract information */
    if (!strncasecmp("Allow", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Allow\n");
	if (!strncmp("204", value_start, 3)) {
	    s->flags.allow_204 = 1;
	} else {
	    debug(81, 3) ("icapOptParseEntry: Allow value unknown");
	}
    } else if (!strncasecmp("Connection", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Connection\n");
    } else if (!strncasecmp("Encapsulated", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Encapsulated\n");
    } else if (!strncasecmp("ISTAG", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found ISTAG\n");
	stringClean(&s->istag);
	stringLimitInit(&s->istag, value_start, value_len);
    } else if (!strncasecmp("Max-Connections", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Max-Connections\n");
	errno = 0;
	new = strtol(value_start, NULL, 10);
	if (errno) {
	    debug(81, 5) ("icapOptParseEntry: Max-Connections: could not parse value\n");
	} else {
	    debug(81, 5) ("icapOptParseEntry: Max-Connections: new value=%d\n", new);
	    s->max_connections = new;
	}
    } else if (!strncasecmp("Methods", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Methods\n");
    } else if (!strncasecmp("Options-TTL", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Options-TTL\n");
	errno = 0;
	new = strtol(value_start, NULL, 10);
	if (errno) {
	    debug(81, 5) ("icapOptParseEntry: Options-TTL: could not parse value\n");
	} else {
	    debug(81, 5) ("icapOptParseEntry: Options-TTL: new value=%d\n", new);
	    s->options_ttl = new;
	}
    } else if (!strncasecmp("Preview", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Preview\n");
	errno = 0;
	new = strtol(value_start, NULL, 10);
	if (errno) {
	    debug(81, 5) ("icapOptParseEntry: Preview: could not parse value\n");
	} else {
	    debug(81, 5) ("icapOptParseEntry: Preview: new value=%d\n", new);
	    s->preview = new;
	}
    } else if (!strncasecmp("Service", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Service\n");
    } else if (!strncasecmp("Service-ID", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Service-ID\n");
    } else if (!strncasecmp("Transfer-Preview", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Transfer-Preview\n");
	stringClean(&s->transfer_preview);
	stringLimitInit(&s->transfer_preview, value_start, value_len);
    } else if (!strncasecmp("Transfer-Ignore", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Transfer-Ignore\n");
	stringClean(&s->transfer_ignore);
	stringLimitInit(&s->transfer_ignore, value_start, value_len);
    } else if (!strncasecmp("Transfer-Complete", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found Transfer-Complete\n");
	stringClean(&s->transfer_complete);
	stringLimitInit(&s->transfer_complete, value_start, value_len);
    } else if (!strncasecmp("X-Include", blk_start, name_len)) {
	debug(81, 5) ("icapOptParseEntry: found X-Include\n");
	if (strstr(value_start, "X-Client-IP")) {
	    debug(81, 5) ("icapOptParseEntry: X-Include: found X-Client-IP\n");
	    s->flags.need_x_client_ip = 1;
        }
	if (strstr(value_start, "X-Authenticated-User")) {
	    debug(81, 5) ("icapOptParseEntry: X-Include: found X-Authenticated-User\n");
	    s->flags.need_x_authenticated_user = 1;
        }
    } else {
	debug(81, 5) ("icapOptParseEntry: unknown options header\n");
    }
}

/* parse OPTIONS reply */
static int
icapOptParseReply(icap_service * s, IcapOptData * i)
{
    int version_major, version_minor;
    const char *str_status;
    int status;
    const char *buf = i->buf;
    const char *parse_start;
    const char *head_end;
    const char *blk_start;
    const char *blk_end;

    if ((status =
            icapParseStatusLine(i->buf, i->offset,
                &version_major, &version_minor, &str_status)) < 0) {
	debug(81, 2) ("icapOptParseReply: bad status line <%s>\n", i->buf);
	return 0;
    }
    debug(81, 3) ("icapOptParseReply: got reply: <ICAP/%d.%d %d %s>\n", version_major, version_minor, status, str_status);

    if (status != 200) {
	debug(81, 3) ("icapOptParseReply: status = %d != 200\n", status);
	return 0;
    }
    parse_start = buf;
    if (i->headlen == 0)
	i->headlen = headersEnd(parse_start, s->opt->offset);

    if (!i->headlen) {
	debug(81, 2) ("icapOptParseReply: end of headers could not be found\n");
	return 0;
    }
    head_end = parse_start + i->headlen - 1;
    while (*(head_end - 1) == '\r')
	head_end--;
    assert(*(head_end - 1) == '\n');
    if (*head_end != '\r' && *head_end != '\n')
	return 0;		/* failure */

    /* skip status line */
    if (!icapIsolateLine(&parse_start, &blk_start, &blk_end)) {
	debug(81, 3) ("icapOptParseReply: failure in isolating status line\n");
	return 0;

    }
    /* now we might start real parsing */
    while (icapIsolateLine(&parse_start, &blk_start, &blk_end)) {
	if (blk_end > head_end || blk_start > head_end || blk_start >= blk_end) {
	    debug(81, 3) ("icapOptParseReply: header limit exceeded. finished.\n");
	    break;
	}
	icapOptParseEntry(s, blk_start, blk_end);
    }
    return 1;
}

static void
icapOptDataInit(IcapOptData * i)
{
    i->buf = memAllocBuf(HTTP_REPLY_BUF_SZ, &i->size);
    i->offset = 0;
    i->headlen = 0;
}

static void
icapOptDataFree(IcapOptData * i)
{
    if (i) {
	memFreeBuf(i->size, i->buf);
	memFree(i, MEM_ICAP_OPT_DATA);
    }
}
