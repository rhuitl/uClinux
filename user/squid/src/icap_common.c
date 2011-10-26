/*
 * $Id$
 *
 * DEBUG: section 81    Internet Content Adaptation Protocol (ICAP) Client
 * AUTHOR: Geetha Manjunath, Hewlett Packard Company
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

/* _GNU_SOURCE is required for strcasestr */
#define _GNU_SOURCE 1

#include "squid.h"
#include "util.h"

extern PF httpStateFree;

#define EXPECTED_ICAP_HEADER_LEN 256
#define ICAP_OPTIONS_REQUEST


void
icapInit()
{
#ifdef ICAP_OPTIONS_REQUEST
    if (Config.icapcfg.onoff) {
	icapOptInit();
    }
#endif
}

void
icapClose()
{
    icapOptShutdown();
}

/*
 * search for a HTTP-like header in the buffer. 
 * Note, buf must be 0-terminated
 *
 * This function is not very good.  It should probably look for
 * header tokens only at the start of a line, not just anywhere in
 * the buffer.
 */
int
icapFindHeader(const char *buf, const char *hdr, const char **Start,
    const char **End)
{
    const char *start = NULL;
    const char *end = NULL;
    start = strcasestr(buf, hdr);
    if (NULL == start)
	return 0;
    end = start + strcspn(start, "\r\n");
    if (start == end)
	return 0;
    *Start = start;
    *End = end;
    return 1;
}

/* 
 * parse the contents of the encapsulated header (buffer between enc_start
 * and enc_end) and put the result into IcapStateData
 */
void
icapParseEncapsulated(IcapStateData * icap, const char *enc_start,
    const char *enc_end)
{
    char *current, *end;

    assert(icap);
    assert(enc_start);
    assert(enc_end);

    current = strchr(enc_start, ':');
    current++;
    while (current < enc_end) {
	while (isspace(*current))
	    current++;
	if (!strncmp(current, "res-hdr=", 8)) {
	    current += 8;
	    icap->enc.res_hdr = strtol(current, &end, 10);
	} else if (!strncmp(current, "req-hdr=", 8)) {
	    current += 8;
	    icap->enc.req_hdr = strtol(current, &end, 10);
	} else if (!strncmp(current, "null-body=", 10)) {
	    current += 10;
	    icap->enc.null_body = strtol(current, &end, 10);
	} else if (!strncmp(current, "res-body=", 9)) {
	    current += 9;
	    icap->enc.res_body = strtol(current, &end, 10);
	} else if (!strncmp(current, "req-body=", 9)) {
	    current += 9;
	    icap->enc.req_body = strtol(current, &end, 10);
	} else if (!strncmp(current, "opt-body=", 9)) {
	    current += 9;
	    icap->enc.opt_body = strtol(current, &end, 10);
	} else {
	    /* invalid header */
	    debug(81, 5) ("icapParseEncapsulated: error in: %s\n", current);
	    return;
	}
	current = end;
	current = strchr(current, ',');
	if (current == NULL)
	    break;
	else
	    current++;		/* skip ',' */
    }
    debug(81,
	3) ("icapParseEncapsulated: res-hdr=%d, req-hdr=%d, null-body=%d, "
	"res-body=%d, req-body=%d, opt-body=%d\n", icap->enc.res_hdr,
	icap->enc.req_hdr, icap->enc.null_body, icap->enc.res_body,
	icap->enc.req_body, icap->enc.opt_body);

}

icap_service *
icapService(icap_service_t type, request_t * r)
{
    icap_service_list *isl_iter;
    int is_iter;
    int nb_unreachable = 0;
    icap_service *unreachable_one = NULL;

    debug(81, 8) ("icapService: type=%s\n", icapServiceToStr(type));
    if (NULL == r) {
	debug(81, 8) ("icapService: no request_t\n");
	return NULL;
    }
    if (NULL == r->class) {
	debug(81, 8) ("icapService: no class\n");
	return NULL;
    }
    for (isl_iter = r->class->isl; isl_iter; isl_iter = isl_iter->next) {
	/* TODO:luc: Do a round-robin, choose a random value ? 
	 * For now, we use a simple round robin with checking is the
	 * icap server is available */
	is_iter = isl_iter->last_service_used;
	do {
	    is_iter = (is_iter + 1) % isl_iter->nservices;
	    debug(81, 8) ("icapService: checking service %s/id=%d\n",
		isl_iter->services[is_iter]->name, is_iter);
	    if (type == isl_iter->services[is_iter]->type) {
		if (!isl_iter->services[is_iter]->unreachable) {
		    debug(81, 8) ("icapService: found service %s/id=%d\n",
			isl_iter->services[is_iter]->name, is_iter);
		    isl_iter->last_service_used = is_iter;
		    return isl_iter->services[is_iter];
		}
		debug(81,
		    8)
		    ("icapService: found service %s/id=%d, but it's unreachable. I don't want to use it\n",
		    isl_iter->services[is_iter]->name, is_iter);
		unreachable_one = isl_iter->services[is_iter];
		nb_unreachable++;
		/* FIXME:luc: in response mod, if we return an NULL pointer, user can bypass
		 * the filter, is it normal ? */
	    }
	} while (is_iter != isl_iter->last_service_used);
    }
    debug(81, 8) ("icapService: no service found\n");
    isl_iter = r->class->isl;

    if (nb_unreachable > 0) {
	debug(81,
	    8)
	    ("All the services are unreachable, returning an unreachable one\n");
	return unreachable_one;
    } else {
	return NULL;
    }
}

int
icapConnect(IcapStateData * icap, CNCB * theCallback)
{
    int rc;
    icap->icap_fd = pconnPop(icap->current_service->hostname,
	icap->current_service->port);
    if (icap->icap_fd >= 0) {
	debug(81, 3) ("icapConnect: reused pconn FD %d\n", icap->icap_fd);
	fd_note(icap->icap_fd, icap->current_service->uri);
	comm_add_close_handler(icap->icap_fd, icapStateFree, icap);
	theCallback(icap->icap_fd, 0, icap);
	return 1;
    }
    icap->icap_fd = comm_open(SOCK_STREAM, 0, getOutgoingAddr(NULL), 0,
	COMM_NONBLOCKING, icap->current_service->uri);
    debug(81, 5) ("icapConnect: new socket, FD %d, local address %s\n",
	icap->icap_fd, inet_ntoa(getOutgoingAddr(NULL)));
    if (icap->icap_fd < 0) {
	icapStateFree(-1, icap);	/* XXX test */
	return 0;
    }
    icap->flags.connect_pending = 1;
    /*
     * Configure timeout and close handler before calling
     * connect because commConnectStart() might get an error
     * immediately and close the descriptor before it returns.
     */
    commSetTimeout(icap->icap_fd, Config.Timeout.connect,
	icapConnectTimeout, icap);
    comm_add_close_handler(icap->icap_fd, icapStateFree, icap);
    /*
     * This sucks.  commConnectStart() may fail before returning,
     * so lets lock the data and check its validity afterwards.
     */
    cbdataLock(icap);
    commConnectStart(icap->icap_fd,
	icap->current_service->hostname,
	icap->current_service->port, theCallback, icap);
    rc = cbdataValid(icap);
    cbdataUnlock(icap);
    debug(81, 3) ("icapConnect: returning %d\n", rc);
    return rc;
}

IcapStateData *
icapAllocate(void)
{
    IcapStateData *icap;

    if (!Config.icapcfg.onoff)
	return 0;

    icap = cbdataAlloc(IcapStateData);
    icap->icap_fd = -1;
    icap->enc.res_hdr = -1;
    icap->enc.res_body = -1;
    icap->enc.req_hdr = -1;
    icap->enc.req_body = -1;
    icap->enc.opt_body = -1;
    icap->enc.null_body = -1;
    icap->chunk_size = -1;
    memBufDefInit(&icap->icap_hdr);

    debug(81, 3) ("New ICAP state\n");
    return icap;
}

void
icapStateFree(int fd, void *data)
{
    IcapStateData *icap = data;
    debug(81, 3) ("icapStateFree: FD %d, icap %p\n", fd, icap);
    assert(icap);
    assert(-1 == fd || fd == icap->icap_fd);
    if (icap->respmod.entry) {
	/*
	 * If we got some error on this side (like ECONNRESET)
	 * we must signal the other side(s) with a storeAbort()
	 * call.
	 */
	if (icap->respmod.entry->store_status != STORE_OK)
	    storeAbort(icap->respmod.entry);
	storeUnlockObject(icap->respmod.entry);
	icap->respmod.entry = NULL;
    }
    requestUnlink(icap->request);
    icap->request = NULL;
    if (!memBufIsNull(&icap->icap_hdr))
	memBufClean(&icap->icap_hdr);
    if (!memBufIsNull(&icap->respmod.buffer))
	memBufClean(&icap->respmod.buffer);
    if (!memBufIsNull(&icap->respmod.req_hdr_copy))
	memBufClean(&icap->respmod.req_hdr_copy);
    if (!memBufIsNull(&icap->respmod.resp_copy))
	memBufClean(&icap->respmod.resp_copy);
    if (!memBufIsNull(&icap->reqmod.hdr_buf))
	memBufClean(&icap->reqmod.hdr_buf);
    if (!memBufIsNull(&icap->reqmod.http_entity.buf))
	memBufClean(&icap->reqmod.http_entity.buf);
    if (!memBufIsNull(&icap->chunk_buf))
	memBufClean(&icap->chunk_buf);
    if (icap->httpState)
	httpStateFree(-1, icap->httpState);
    cbdataUnlock(icap->reqmod.client_cookie);
    cbdataFree(icap);
}

void
icapConnectTimeout(int fd, void *data)
{
    IcapStateData *icap = data;
    debug(81, 3) ("icapConnectTimeout: FD %d, unreachable=1\n", fd);
    assert(fd == icap->icap_fd);
    icapOptSetUnreachable(icap->current_service);
    comm_close(fd);
}

void
icapReadTimeout(int fd, void *data)
{
    IcapStateData *icap = data;
    assert(fd == icap->icap_fd);
    if (icap->flags.wait_for_preview_reply || icap->flags.http_server_eof) {
	debug(81, 3) ("icapReadTimeout: FD %d, unreachable=1\n", fd);
	icapOptSetUnreachable(icap->current_service);
    } else
	debug(81, 3) ("icapReadTimeout: FD %d, still reachable\n", fd);
    comm_close(fd);
}

icap_service_t
icapServiceToType(const char *s)
{
    if (!strcmp(s, "reqmod_precache"))
	return ICAP_SERVICE_REQMOD_PRECACHE;
    if (!strcmp(s, "reqmod_postcache"))
	return ICAP_SERVICE_REQMOD_POSTCACHE;
    if (!strcmp(s, "respmod_precache"))
	return ICAP_SERVICE_RESPMOD_PRECACHE;
    if (!strcmp(s, "respmod_postcache"))
	return ICAP_SERVICE_RESPMOD_POSTCACHE;
    return ICAP_SERVICE_MAX;
}

const char *
icapServiceToStr(const icap_service_t type)
{
    if (type >= 0 && type < ICAP_SERVICE_MAX)
	return icap_service_type_str[type];
    else
	return "error";
}


/* copied from clientAclChecklistCreate */
static aclCheck_t *
icapAclChecklistCreate(const acl_access * acl, const clientHttpRequest * http)
{
    aclCheck_t *ch;
    ConnStateData *conn = http->conn;
    ch = aclChecklistCreate(acl, http->request, 0);
    ch->conn = conn;
    cbdataLock(ch->conn);
    return ch;
}

/*
 * check wether we do icap for a request
 */
int
icapCheckAcl(clientHttpRequest * http)
{
    icap_access *iter;
    aclCheck_t *icapChecklist;

    for (iter = Config.icapcfg.access_head; iter; iter = iter->next) {
	acl_access *A = iter->access;
	icapChecklist = icapAclChecklistCreate(A, http);
	if (aclMatchAclList(A->acl_list, icapChecklist)) {
	    debug(81, 5) ("icapCheckAcl: match for class=%s\n",
		iter->class->name);
	    if (A->allow) {
		/* allow rule, do icap and use associated class */
		http->request->class = iter->class;
		aclChecklistFree(icapChecklist);
		return 1;
	    } else {
		/* deny rule, stop processing */
		aclChecklistFree(icapChecklist);
		return 0;
	    }
	}
	aclChecklistFree(icapChecklist);
    }
    return 0;
}

/* icapLineLength
 *
 * returns the amount of data until lineending ( \r\n )
 * This function is NOT tolerant of variations of \r\n.
 */
size_t
icapLineLength(const char *start, int len)
{
    size_t lineLen = 0;
    char *end = (char *) memchr(start, '\r', len);
    if (NULL == end)
	return 0;
    end++;			/* advance to where '\n' should be */
    lineLen = end - start + 1;
    if (lineLen > len) {
	debug(0, 0) ("icapLineLength: warning lineLen (%d) > len (%d)\n",
	    lineLen, len);
	return 0;
    }
    if (*end != '\n') {
	debug(0, 0) ("icapLineLength: warning *end (%x) != '\\n'\n", *end);
	return 0;
    }
    debug(81, 7) ("icapLineLength: returning %d\n", lineLen);
    return lineLen;
}

/*
 * return:
 *   -1 if EOF before getting end of ICAP header
 *    0 if we don't have the entire ICAP header yet
 *    1 if we got the whole header
 */
int
icapReadHeader(int fd, IcapStateData * icap, int *isIcap)
{
    int headlen = 0;
    int len = 0;
    int peek_sz = EXPECTED_ICAP_HEADER_LEN;
    int read_sz = 0;
    LOCAL_ARRAY(char, tmpbuf, SQUID_TCP_SO_RCVBUF);
    for (;;) {
	len = recv(fd, tmpbuf, peek_sz, MSG_PEEK);
	debug(81, 5) ("recv(FD %d, ..., MSG_PEEK) ret %d\n", fd, len);
	if (len < 0) {
	    debug(81, 1) ("icapReadHeader: FD %d recv error: %s\n", fd,
		xstrerror());
	    return -1;
	}
	if (len == 0) {
	    debug(81, 2) ("icapReadHeader: FD %d recv EOF\n", fd);
	    return -1;
	}
	headlen = headersEnd(tmpbuf, len);
	debug(81, 3) ("headlen=%d\n", headlen);
	/*
	 * break if we now know where the ICAP headers end
	 */
	if (headlen)
	    break;
	/*
	 * break if we know there is no more data to read
	 */
	if (len < peek_sz)
	    break;
	/*
	 * The ICAP header is larger than (or equal to) our read
	 * buffer, so double it and try to peek again.
	 */
	peek_sz *= 2;
	if (peek_sz >= SQUID_TCP_SO_RCVBUF) {
	    debug(81,
		1) ("icapReadHeader: Failed to find end of ICAP header\n");
	    debug(81, 1) ("\twithin first %d bytes of response\n",
		SQUID_TCP_SO_RCVBUF);
	    debug(81, 1) ("\tpossible persistent connection bug/confusion\n");
	    return -1;
	}
    }
    /*
     * Now actually read the data from the kernel
     */
    if (headlen)
	read_sz = headlen;
    else
	read_sz = len;
    len = FD_READ_METHOD(fd, tmpbuf, read_sz);
    assert(len == read_sz);
    fd_bytes(fd, len, FD_READ);
    memBufAppend(&icap->icap_hdr, tmpbuf, len);
    if (headlen) {
	/* End of ICAP header found */
	if (icap->icap_hdr.size < 4)
	    *isIcap = 0;
	else if (0 == strncmp(icap->icap_hdr.buf, "ICAP", 4))
	    *isIcap = 1;
	else
	    *isIcap = 0;
	return 1;
    }
    /*
     * We don't have all the headers yet
     */
    return 0;
}

static int
icapParseConnectionClose(const IcapStateData * icap, const char *s,
    const char *e)
{
    char *t;
    char *q;
    /*
     * s points to the start of the line "Connection: ... "
     * e points to *after* the last character on the line
     */
    s += 11;			/* skip past Connection: */
    while (s < e && isspace(*s))
	s++;
    if (e - s < 5)
	return 0;
    /*
     * create a buffer that we can use strtok on
     */
    t = xmalloc(e - s + 1);
    strncpy(t, s, e - s);
    *(t + (e - s)) = '\0';
    for (q = strtok(t, ","); q; q = strtok(NULL, ",")) {
	 if (0 == strcasecmp(q, "close")){
	      xfree(t);
	    return 1;
	 }
    }
    xfree(t);
    return 0;
}

/* returns icap status, version and subversion extracted from status line or -1 on parsing failure 
 * The str_status pointr points to the text returned from the icap server.
 * sline probably is NOT terminated with '\0' 
 */
int
icapParseStatusLine(const char *sline, int slinesize, int *version_major,
    int *version_minor, const char **str_status)
{
    char *sp, *stmp, *ep = (char *) sline + slinesize;
    int status;
    if (slinesize < 14)		/*The format of this line is: "ICAP/x.x xxx[ msg....]\r\n" */
	return -1;

    if (strncmp(sline, "ICAP/", 5) != 0)
	return -1;
    if (sscanf(sline + 5, "%d.%d", version_major, version_minor) != 2)
	return -1;

    if (!(sp = memchr(sline, ' ', slinesize)))
	return -1;

    while (sp < ep && xisspace(*++sp));

    if (!xisdigit(*sp) || sp >= ep)
	return -1;

    if ((status = strtol(sp, &stmp, 10)) <= 0)
	return -1;
    sp = stmp;

    while (sp < ep && xisspace(*++sp));
    *str_status = sp;
    /*Must add a test for "\r\n" end headers .... */
    return status;
}


void
icapSetKeepAlive(IcapStateData * icap, const char *hdrs)
{
    const char *start;
    const char *end;
    if (0 == icap->flags.keep_alive)
	return;
    if (0 == icapFindHeader(hdrs, "Connection:", &start, &end)) {
	icap->flags.keep_alive = 1;
	return;
    }
    if (icapParseConnectionClose(icap, start, end))
	icap->flags.keep_alive = 0;
    else
	icap->flags.keep_alive = 1;
}

/*
 * icapParseChunkSize
 *
 * Returns the offset where the next chunk starts
 * return parameter chunk_size;
 */
static int
icapParseChunkSize(const char *buf, int len, int *chunk_size)
{
    int chunkSize = 0;
    char c;
    size_t start;
    size_t end;
    size_t nextStart = 0;
    debug(81, 3) ("icapParseChunkSize: buf=%p, len=%d\n", buf, len);
    do {
	start = nextStart;
	debug(81, 3) ("icapParseChunkSize: start=%d\n", start);
	if (len <= start) {
	    /*
	     * end of buffer, so far no lines or only empty lines,
	     * wait for more data. read chunk size with next buffer.
	     */
	    *chunk_size = 0;
	    return 0;
	}
	end = start + icapLineLength(buf + start, len - start);
	nextStart = end;
	if (end <= start) {
	    /*
	     * no line found, need more code here, now we are in
	     * deep trouble, buffer stops with half a chunk size
	     * line. For now stop here.
	     */
	    debug(81, 1) ("icapParseChunkSize: WARNING in mid-line, ret 0\n");
	    *chunk_size = 0;
	    return 0;
	}
	while (start < end) {
	    if (NULL == strchr(w_space, buf[start]))
		break;
	    start++;
	}
	while (start < end) {
	    if (NULL == strchr(w_space, buf[end - 1]))
		break;
	    end--;
	}
	/*
	 * if now end <= start we got an empty line. The previous
	 * chunk data should stop with a CRLF. In case that the
	 * other end does not follow the specs and sends no CRLF
	 * or too many empty lines, just continue till we have a
	 * non-empty line.
	 */
    } while (end <= start);
    debug(81, 3) ("icapParseChunkSize: start=%d, end=%d\n", start, end);

    /* Non-empty line: Parse the chunk size */
    while (start < end) {
	c = buf[start++];
	if (c >= 'a' && c <= 'f') {
	    chunkSize = chunkSize * 16 + c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
	    chunkSize = chunkSize * 16 + c - 'A' + 10;
	} else if (c >= '0' && c <= '9') {
	    chunkSize = chunkSize * 16 + c - '0';
	} else {
	    if (!(c == ';' || c == ' ' || c == '\t')) {
		/*Syntax error: Chunksize expected. */
		*chunk_size = -2;	/* we are done */
		return nextStart;
	    }
	    /* Next comes a chunk extension */
	    break;
	}
    }
    /*
     * if we read a zero chunk, we reached the end. Mark this for
     * icapPconnTransferDone
     */
    *chunk_size = (chunkSize > 0) ? chunkSize : -2;
    debug(81, 3) ("icapParseChunkSize: return nextStart=%d\n", nextStart);
    return nextStart;
}

/*
 * icapParseChunkedBody
 *
 * De-chunk an HTTP entity received from the ICAP server.
 * The 'store' function pointer is storeAppend() or memBufAppend().
 */
size_t
icapParseChunkedBody(IcapStateData * icap, STRCB * store, void *store_data)
{
    int bufOffset = 0;
    size_t bw = 0;
    MemBuf *cb = &icap->chunk_buf;
    const char *buf = cb->buf;
    int len = cb->size;

    if (icap->chunk_size == -2) {
	debug(81, 3) ("zero end chunk reached\n");
	return 0;
    }
    debug(81, 3) ("%s:%d: chunk_size=%d\n", __FILE__, __LINE__,
	icap->chunk_size);
    if (icap->chunk_size < 0) {
	store(store_data, buf, len);
	cb->size = 0;
	return (size_t) len;
    }
    debug(81, 3) ("%s:%d: bufOffset=%d, len=%d\n", __FILE__, __LINE__,
	bufOffset, len);
    while (bufOffset < len) {
	debug(81, 3) ("%s:%d: bufOffset=%d, len=%d\n", __FILE__, __LINE__,
	    bufOffset, len);
	if (icap->chunk_size == 0) {
	    int x;
	    x = icapParseChunkSize(buf + bufOffset,
		len - bufOffset, &icap->chunk_size);
	    if (x < 1) {
		/* didn't find a valid chunk spec */
		break;
	    }
	    bufOffset += x;
	    debug(81, 3) ("got chunksize %d, new offset %d\n",
		icap->chunk_size, bufOffset);
	    if (icap->chunk_size == -2) {
		debug(81, 3) ("zero end chunk reached\n");
		break;
	    }
	}
	debug(81, 3) ("%s:%d: X\n", __FILE__, __LINE__);
	if (icap->chunk_size > 0) {
	    if (icap->chunk_size >= len - bufOffset) {
		store(store_data, buf + bufOffset, len - bufOffset);
		bw += (len - bufOffset);
		icap->chunk_size -= (len - bufOffset);
		bufOffset = len;
	    } else {
		store(store_data, buf + bufOffset, icap->chunk_size);
		bufOffset += icap->chunk_size;
		bw += icap->chunk_size;
		icap->chunk_size = 0;
	    }
	}
    }
    if (0 == bufOffset) {
	(void) 0;
    } else if (bufOffset == cb->size) {
	cb->size = 0;
    } else {
	assert(bufOffset <= cb->size);
	xmemmove(cb->buf, cb->buf + bufOffset, cb->size - bufOffset);
	cb->size -= bufOffset;
    }
    return bw;
}

/*
 *  icapAddAuthUserHeader
 *
 *  Builds and adds the X-Authenticated-User header to an ICAP request headers.
 */
void
icapAddAuthUserHeader(MemBuf * mb, auth_user_request_t * auth_user_request)
{
    char *user = authenticateUserRequestUsername(auth_user_request);
    char *authuser;
    size_t len, userlen, schemelen, userofslen;
    char *userofs;

    if (user == NULL) {
	debug(81, 5) ("icapAddAuthUserHeader: NULL username\n");
	return;
    }
    userlen = strlen(user);
    schemelen = strlen(Config.icapcfg.auth_scheme);
    len = userlen + schemelen + 1;
    authuser = xcalloc(len, 1);

    if ((userofs = strstr(Config.icapcfg.auth_scheme, "%u")) == NULL) {
	/* simply add user at end of string */
	snprintf(authuser, len, "%s%s", Config.icapcfg.auth_scheme, user);
    } else {
	userofslen = userofs - Config.icapcfg.auth_scheme;
	xmemcpy(authuser, Config.icapcfg.auth_scheme, userofslen);
	xmemcpy(authuser + userofslen, user, userlen);
	xmemcpy(authuser + userofslen + userlen,
	    userofs + 2, schemelen - (userofslen + 2) + 1);
    }

    memBufPrintf(mb, "X-Authenticated-User: %s\r\n", base64_encode(authuser));
    xfree(authuser);
}
