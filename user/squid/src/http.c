
/*
 * $Id: http.c,v 1.384.2.30 2005/03/26 02:50:53 hno Exp $
 *
 * DEBUG: section 11    Hypertext Transfer Protocol (HTTP)
 * AUTHOR: Harvest Derived
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

/*
 * Anonymizing patch by lutz@as-node.jena.thur.de
 * have a look into http-anon.c to get more informations.
 */

#include "squid.h"

static const char *const crlf = "\r\n";

static CWCB httpSendComplete;
static CWCB httpSendRequestEntry;

static PF httpReadReply;
static void httpSendRequest(HttpStateData *);
PF httpStateFree;
static PF httpTimeout;
static void httpCacheNegatively(StoreEntry *);
static void httpMakePrivate(StoreEntry *);
static void httpMakePublic(StoreEntry *);
static int httpCachableReply(HttpStateData *);
static void httpMaybeRemovePublic(StoreEntry *, http_status);

void
httpStateFree(int fd, void *data)
{
    HttpStateData *httpState = data;
#if DELAY_POOLS
    if (fd >= 0)
	delayClearNoDelay(fd);
#endif
    if (httpState == NULL)
	return;
    if (httpState->body_buf) {
	requestAbortBody(httpState->orig_request);
	if (httpState->body_buf) {
	    memFree(httpState->body_buf, MEM_8K_BUF);
	    httpState->body_buf = NULL;
	}
    }
    storeUnlockObject(httpState->entry);
    if (!memBufIsNull(&httpState->reply_hdr)) {
	memBufClean(&httpState->reply_hdr);
    }
    requestUnlink(httpState->request);
    requestUnlink(httpState->orig_request);
    httpState->request = NULL;
    httpState->orig_request = NULL;
#if HS_FEAT_ICAP
    cbdataUnlock(httpState->icap_writer);
#endif
    cbdataFree(httpState);
}

int
httpCachable(method_t method)
{
    /* GET and HEAD are cachable. Others are not. */
    if (method != METHOD_GET && method != METHOD_HEAD)
	return 0;
    /* else cachable */
    return 1;
}

static void
httpTimeout(int fd, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = httpState->entry;
    debug(11, 4) ("httpTimeout: FD %d: '%s'\n", fd, storeUrl(entry));
    if (entry->store_status == STORE_PENDING) {
	if (entry->mem_obj->inmem_hi == 0) {
	    fwdFail(httpState->fwd,
		errorCon(ERR_READ_TIMEOUT, HTTP_GATEWAY_TIMEOUT));
	}
    }
    comm_close(fd);
}

/* This object can be cached for a long time */
static void
httpMakePublic(StoreEntry * entry)
{
    if (EBIT_TEST(entry->flags, ENTRY_CACHABLE))
	storeSetPublicKey(entry);
}

/* This object should never be cached at all */
static void
httpMakePrivate(StoreEntry * entry)
{
    storeExpireNow(entry);
    storeReleaseRequest(entry);	/* delete object when not used */
    /* storeReleaseRequest clears ENTRY_CACHABLE flag */
}

/* This object may be negatively cached */
static void
httpCacheNegatively(StoreEntry * entry)
{
    storeNegativeCache(entry);
    if (EBIT_TEST(entry->flags, ENTRY_CACHABLE))
	storeSetPublicKey(entry);
}

static void
httpMaybeRemovePublic(StoreEntry * e, http_status status)
{
    int remove = 0;
    int forbidden = 0;
    StoreEntry *pe;
    if (!EBIT_TEST(e->flags, KEY_PRIVATE))
	return;
    switch (status) {
    case HTTP_OK:
    case HTTP_NON_AUTHORITATIVE_INFORMATION:
    case HTTP_MULTIPLE_CHOICES:
    case HTTP_MOVED_PERMANENTLY:
    case HTTP_MOVED_TEMPORARILY:
    case HTTP_GONE:
    case HTTP_NOT_FOUND:
	remove = 1;
	break;
    case HTTP_FORBIDDEN:
    case HTTP_METHOD_NOT_ALLOWED:
	forbidden = 1;
	break;
#if WORK_IN_PROGRESS
    case HTTP_UNAUTHORIZED:
	forbidden = 1;
	break;
#endif
    default:
#if QUESTIONABLE
	/*
	 * Any 2xx response should eject previously cached entities...
	 */
	if (status >= 200 && status < 300)
	    remove = 1;
#endif
	break;
    }
    if (!remove && !forbidden)
	return;
    assert(e->mem_obj);
    if (e->mem_obj->request)
	pe = storeGetPublicByRequest(e->mem_obj->request);
    else
	pe = storeGetPublic(e->mem_obj->url, e->mem_obj->method);
    if (pe != NULL) {
	assert(e != pe);
	storeRelease(pe);
    }
    /*
     * Also remove any cached HEAD response in case the object has
     * changed.
     */
    if (e->mem_obj->request)
	pe = storeGetPublicByRequestMethod(e->mem_obj->request, METHOD_HEAD);
    else
	pe = storeGetPublic(e->mem_obj->url, METHOD_HEAD);
    if (pe != NULL) {
	assert(e != pe);
	storeRelease(pe);
    }
    if (forbidden)
	return;
    switch (e->mem_obj->method) {
    case METHOD_PUT:
    case METHOD_DELETE:
    case METHOD_PROPPATCH:
    case METHOD_MKCOL:
    case METHOD_MOVE:
    case METHOD_BMOVE:
    case METHOD_BDELETE:
	/*
	 * Remove any cached GET object if it is beleived that the
	 * object may have changed as a result of other methods
	 */
	if (e->mem_obj->request)
	    pe = storeGetPublicByRequestMethod(e->mem_obj->request, METHOD_GET);
	else
	    pe = storeGetPublic(e->mem_obj->url, METHOD_GET);
	if (pe != NULL) {
	    assert(e != pe);
	    storeRelease(pe);
	}
	break;
    }
}

static int
httpCachableReply(HttpStateData * httpState)
{
    HttpReply *rep = httpState->entry->mem_obj->reply;
    HttpHeader *hdr = &rep->header;
    const int cc_mask = (rep->cache_control) ? rep->cache_control->mask : 0;
    const char *v;
    if (EBIT_TEST(cc_mask, CC_PRIVATE))
	return 0;
    if (EBIT_TEST(cc_mask, CC_NO_CACHE))
	return 0;
    if (EBIT_TEST(cc_mask, CC_NO_STORE))
	return 0;
    if (httpState->request->flags.auth) {
	/*
	 * Responses to requests with authorization may be cached
	 * only if a Cache-Control: public reply header is present.
	 * RFC 2068, sec 14.9.4
	 */
	if (!EBIT_TEST(cc_mask, CC_PUBLIC))
	    return 0;
    }
    /* Pragma: no-cache in _replies_ is not documented in HTTP,
     * but servers like "Active Imaging Webcast/2.0" sure do use it */
    if (httpHeaderHas(hdr, HDR_PRAGMA)) {
	String s = httpHeaderGetList(hdr, HDR_PRAGMA);
	const int no_cache = strListIsMember(&s, "no-cache", ',');
	stringClean(&s);
	if (no_cache)
	    return 0;
    }
    /*
     * The "multipart/x-mixed-replace" content type is used for
     * continuous push replies.  These are generally dynamic and
     * probably should not be cachable
     */
    if ((v = httpHeaderGetStr(hdr, HDR_CONTENT_TYPE)))
	if (!strncasecmp(v, "multipart/x-mixed-replace", 25))
	    return 0;
    switch (httpState->entry->mem_obj->reply->sline.status) {
	/* Responses that are cacheable */
    case HTTP_OK:
    case HTTP_NON_AUTHORITATIVE_INFORMATION:
    case HTTP_MULTIPLE_CHOICES:
    case HTTP_MOVED_PERMANENTLY:
    case HTTP_GONE:
	/*
	 * Don't cache objects that need to be refreshed on next request,
	 * unless we know how to refresh it.
	 */
	if (!refreshIsCachable(httpState->entry))
	    return 0;
	/* don't cache objects from peers w/o LMT, Date, or Expires */
	/* check that is it enough to check headers @?@ */
	if (rep->date > -1)
	    return 1;
	else if (rep->last_modified > -1)
	    return 1;
	else if (!httpState->peer)
	    return 1;
	/* @?@ (here and 302): invalid expires header compiles to squid_curtime */
	else if (rep->expires > -1)
	    return 1;
	else
	    return 0;
	/* NOTREACHED */
	break;
	/* Responses that only are cacheable if the server says so */
    case HTTP_MOVED_TEMPORARILY:
	if (rep->expires > -1)
	    return 1;
	else
	    return 0;
	/* NOTREACHED */
	break;
	/* Errors can be negatively cached */
    case HTTP_NO_CONTENT:
    case HTTP_USE_PROXY:
    case HTTP_BAD_REQUEST:
    case HTTP_FORBIDDEN:
    case HTTP_NOT_FOUND:
    case HTTP_METHOD_NOT_ALLOWED:
    case HTTP_REQUEST_URI_TOO_LARGE:
    case HTTP_INTERNAL_SERVER_ERROR:
    case HTTP_NOT_IMPLEMENTED:
    case HTTP_BAD_GATEWAY:
    case HTTP_SERVICE_UNAVAILABLE:
    case HTTP_GATEWAY_TIMEOUT:
	return -1;
	/* NOTREACHED */
	break;
	/* Some responses can never be cached */
    case HTTP_PARTIAL_CONTENT:	/* Not yet supported */
    case HTTP_SEE_OTHER:
    case HTTP_NOT_MODIFIED:
    case HTTP_UNAUTHORIZED:
    case HTTP_PROXY_AUTHENTICATION_REQUIRED:
    case HTTP_INVALID_HEADER:	/* Squid header parsing error */
    case HTTP_HEADER_TOO_LARGE:
    default:			/* Unknown status code */
	return 0;
	/* NOTREACHED */
	break;
    }
    /* NOTREACHED */
}

/*
 * For Vary, store the relevant request headers as 
 * virtual headers in the reply
 * Returns false if the variance cannot be stored
 */
const char *
httpMakeVaryMark(request_t * request, HttpReply * reply)
{
    String vary, hdr;
    const char *pos = NULL;
    const char *item;
    const char *value;
    int ilen;
    static String vstr =
    {0, 0, NULL};

    stringClean(&vstr);
    vary = httpHeaderGetList(&reply->header, HDR_VARY);
    while (strListGetItem(&vary, ',', &item, &ilen, &pos)) {
	char *name = xmalloc(ilen + 1);
	xstrncpy(name, item, ilen + 1);
	Tolower(name);
	if (strcmp(name, "*") == 0) {
	    /* Can not handle "Vary: *" withtout ETag support */
	    safe_free(name);
	    stringClean(&vary);
	    stringClean(&vstr);
	    break;
	}
	strListAdd(&vstr, name, ',');
	hdr = httpHeaderGetByName(&request->header, name);
	safe_free(name);
	value = strBuf(hdr);
	if (value) {
	    value = rfc1738_escape_part(value);
	    stringAppend(&vstr, "=\"", 2);
	    stringAppend(&vstr, value, strlen(value));
	    stringAppend(&vstr, "\"", 1);
	}
	stringClean(&hdr);
    }
    stringClean(&vary);
#if X_ACCELERATOR_VARY
    pos = NULL;
    vary = httpHeaderGetList(&reply->header, HDR_X_ACCELERATOR_VARY);
    while (strListGetItem(&vary, ',', &item, &ilen, &pos)) {
	char *name = xmalloc(ilen + 1);
	xstrncpy(name, item, ilen + 1);
	Tolower(name);
	strListAdd(&vstr, name, ',');
	hdr = httpHeaderGetByName(&request->header, name);
	safe_free(name);
	value = strBuf(hdr);
	if (value) {
	    value = rfc1738_escape_part(value);
	    stringAppend(&vstr, "=\"", 2);
	    stringAppend(&vstr, value, strlen(value));
	    stringAppend(&vstr, "\"", 1);
	}
	stringClean(&hdr);
    }
    stringClean(&vary);
#endif
    debug(11, 3) ("httpMakeVaryMark: %s\n", strBuf(vstr));
    return strBuf(vstr);
}

/* rewrite this later using new interfaces @?@ */
void
httpProcessReplyHeader(HttpStateData * httpState, const char *buf, int size)
{
    StoreEntry *entry = httpState->entry;
    size_t hdr_len;
    size_t hdr_size;
    HttpReply *reply = entry->mem_obj->reply;
    Ctx ctx = ctx_enter(entry->mem_obj->url);
    debug(11, 3) ("httpProcessReplyHeader: key '%s'\n",
	storeKeyText(entry->hash.key));
    if (memBufIsNull(&httpState->reply_hdr))
	memBufDefInit(&httpState->reply_hdr);
    assert(httpState->reply_hdr_state == 0);
    memBufAppend(&httpState->reply_hdr, buf, size);
    hdr_len = httpState->reply_hdr.size;
    if (hdr_len > 4 && strncmp(httpState->reply_hdr.buf, "HTTP/", 5)) {
	debug(11, 3) ("httpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", httpState->reply_hdr.buf);
	httpState->reply_hdr_state += 2;
	memBufClean(&httpState->reply_hdr);
	httpBuildVersion(&reply->sline.version, 0, 9);
	reply->sline.status = HTTP_INVALID_HEADER;
	ctx_exit(ctx);
	return;
    }
    hdr_size = headersEnd(httpState->reply_hdr.buf, hdr_len);
    if (hdr_size)
	hdr_len = hdr_size;
    if (hdr_len > Config.maxReplyHeaderSize) {
	debug(11, 1) ("httpProcessReplyHeader: Too large reply header\n");
	if (!memBufIsNull(&httpState->reply_hdr))
	    memBufClean(&httpState->reply_hdr);
	reply->sline.status = HTTP_HEADER_TOO_LARGE;
	httpState->reply_hdr_state += 2;
	ctx_exit(ctx);
	return;
    }
    /* headers can be incomplete only if object still arriving */
    if (!hdr_size) {
	if (httpState->eof)
	    hdr_size = hdr_len;
	else {
	    ctx_exit(ctx);
	    return;		/* headers not complete */
	}
    }
    /* Cut away any excess body data (only needed for debug?) */
    memBufAppend(&httpState->reply_hdr, "\0", 1);
    httpState->reply_hdr.buf[hdr_size] = '\0';
    httpState->reply_hdr_state++;
    assert(httpState->reply_hdr_state == 1);
    httpState->reply_hdr_state++;
    debug(11, 9) ("GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
	httpState->reply_hdr.buf);
    /* Parse headers into reply structure */
    /* what happens if we fail to parse here? */
    httpReplyParse(reply, httpState->reply_hdr.buf, hdr_size);
    if (reply->sline.status >= HTTP_INVALID_HEADER) {
	debug(11, 3) ("httpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", httpState->reply_hdr.buf);
	memBufClean(&httpState->reply_hdr);
	ctx_exit(ctx);
	return;
    }
    storeTimestampsSet(entry);
    /* Check if object is cacheable or not based on reply code */
    debug(11, 3) ("httpProcessReplyHeader: HTTP CODE: %d\n", reply->sline.status);
    if (neighbors_do_private_keys)
	httpMaybeRemovePublic(entry, reply->sline.status);
    if (httpHeaderHas(&reply->header, HDR_VARY)
#if X_ACCELERATOR_VARY
	|| httpHeaderHas(&reply->header, HDR_X_ACCELERATOR_VARY)
#endif
	) {
	const char *vary = httpMakeVaryMark(httpState->orig_request, reply);
	if (!vary) {
	    httpMakePrivate(entry);
	    goto no_cache;
	}
	entry->mem_obj->vary_headers = xstrdup(vary);
    }
    switch (httpCachableReply(httpState)) {
    case 1:
	httpMakePublic(entry);
	break;
    case 0:
	httpMakePrivate(entry);
	break;
    case -1:
	if (Config.negativeTtl > 0)
	    httpCacheNegatively(entry);
	else
	    httpMakePrivate(entry);
	break;
    default:
	assert(0);
	break;
    }
  no_cache:
    if (reply->cache_control) {
	if (EBIT_TEST(reply->cache_control->mask, CC_PROXY_REVALIDATE))
	    EBIT_SET(entry->flags, ENTRY_REVALIDATE);
	else if (EBIT_TEST(reply->cache_control->mask, CC_MUST_REVALIDATE))
	    EBIT_SET(entry->flags, ENTRY_REVALIDATE);
    }
    if (httpState->flags.keepalive)
	if (httpState->peer)
	    httpState->peer->stats.n_keepalives_sent++;
    if (reply->keep_alive) {
	if (httpState->peer)
	    httpState->peer->stats.n_keepalives_recv++;
	if (Config.onoff.detect_broken_server_pconns && httpReplyBodySize(httpState->request->method, reply) == -1) {
	    debug(11, 1) ("httpProcessReplyHeader: Impossible keep-alive header from '%s'\n", storeUrl(entry));
	    debug(11, 2) ("GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
		httpState->reply_hdr.buf);
	    httpState->flags.keepalive_broken = 1;
	}
    }
    if (reply->date > -1 && !httpState->peer) {
	int skew = abs(reply->date - squid_curtime);
	if (skew > 86400)
	    debug(11, 3) ("%s's clock is skewed by %d seconds!\n",
		httpState->request->host, skew);
    }
    ctx_exit(ctx);
#if HEADERS_LOG
    headersLog(1, 0, httpState->request->method, reply);
#endif
}

static int
httpPconnTransferDone(HttpStateData * httpState)
{
    /* return 1 if we got the last of the data on a persistent connection */
    MemObject *mem = httpState->entry->mem_obj;
    HttpReply *reply = mem->reply;
    squid_off_t clen;
    squid_off_t content_bytes_read;
    debug(11, 3) ("httpPconnTransferDone: FD %d\n", httpState->fd);
    debug(11, 5) ("httpPconnTransferDone: content_length=%" PRINTF_OFF_T "\n",
	reply->content_length);
    /* If we haven't seen the end of reply headers, we are not done */
    if (httpState->reply_hdr_state < 2) {
	debug(11, 3) ("httpPconnTransferDone: reply_hdr_state=%d, returning 0\n",
	    httpState->reply_hdr_state);
	return 0;
    }
    clen = httpReplyBodySize(httpState->request->method, reply);
#ifdef HS_FEAT_ICAP
    if (httpState->icap_writer) {
	 content_bytes_read = httpState->icap_writer->fake_content_length;
	 debug(11, 3) ("using fake conten length %" PRINTF_OFF_T "\n", content_bytes_read);
    }
    else
#endif
	 content_bytes_read = mem->inmem_hi;
    /* If the body size is unknown we must wait for EOF */
    if (clen < 0)
	return 0;
    /* Barf if we got more than we asked for */
    if (content_bytes_read > clen + reply->hdr_sz)
	return -1;
    /* If there is no message body, we can be persistent */
    if (0 == clen)
	return 1;
    /* If the body size is known, we must wait until we've gotten all of it.  */
    if (content_bytes_read < clen + reply->hdr_sz)
	return 0;
    /* We got it all */
    return 1;
}

/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
/* XXX this function is too long! */
static void
httpReadReply(int fd, void *data)
{
    HttpStateData *httpState = data;
    LOCAL_ARRAY(char, buf, SQUID_TCP_SO_RCVBUF);
    StoreEntry *entry = httpState->entry;
    const request_t *request = httpState->request;
    int len;
    int bin;
    int clen;
    size_t read_sz;
#if DELAY_POOLS
    delay_id delay_id;

    /* special "if" only for http (for nodelay proxy conns) */
    if (delayIsNoDelay(fd))
	delay_id = 0;
    else
	delay_id = delayMostBytesAllowed(entry->mem_obj);
#endif
    debug(11, 5) ("httpReadReply: FD %d: httpState %p.\n", fd, data);
#if HS_FEAT_ICAP
    if (httpState->icap_writer) {
	 if (!httpState->icap_writer->respmod.entry) {
	      debug(11, 3) ("httpReadReply: FD: %d: icap respmod aborded!\n", fd);
	      comm_close(fd);
	      return;
	 }
	 /*The folowing entry can not be marked as aborted.  
	   The StoreEntry icap_writer->respmod.entry used when the icap_write used......*/
    } 
    else
#endif
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	comm_close(fd);
	return;
    }
    /* check if we want to defer reading */
    errno = 0;
    read_sz = SQUID_TCP_SO_RCVBUF;
#if DELAY_POOLS
    read_sz = delayBytesWanted(delay_id, 1, read_sz);
#endif
#if HS_FEAT_ICAP
    if (httpState->icap_writer) {
       IcapStateData * icap = httpState->icap_writer;
       /*
	* Ok we have a received a response from the web server, so try to 
	* connect the icap server if it's the first attemps. If we try
	* to connect to the icap server, defer this request (do not read
	* the buffer), and defer until icapConnectOver() is not called.
	*/
       if (icap->flags.connect_requested == 0) {
	  debug(81, 2) ("icapSendRespMod: Create a new connection to icap server\n");
	  if (!icapConnect(icap, icapConnectOver))
	   {
	     debug(81, 2) ("icapSendRespMod: Something strange while creating a socket to icap server\n");
	     commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	     return;
	   }
	  debug(81, 2) ("icapSendRespMod: new connection to icap server (using FD=%d)\n",icap->icap_fd);
	  icap->flags.connect_requested = 1;
	  /* Wait for more data or EOF condition */
	  commSetTimeout(fd, httpState->flags.keepalive_broken?10:Config.Timeout.read, NULL, NULL);
	  commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	  return;
       }
    }
#endif

    statCounter.syscalls.sock.reads++;
    len = FD_READ_METHOD(fd, buf, read_sz);
    debug(11, 5) ("httpReadReply: FD %d: len %d.\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
#if DELAY_POOLS
	delayBytesIn(delay_id, len);
#endif
	kb_incr(&statCounter.server.all.kbytes_in, len);
	kb_incr(&statCounter.server.http.kbytes_in, len);
	IOStats.Http.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Http.read_hist[bin]++;
    }
#ifdef HS_FEAT_ICAP
    if (httpState->icap_writer)
	(void) 0;
    else
#endif

    if (!httpState->reply_hdr.size && len > 0 && fd_table[fd].uses > 1) {
	/* Skip whitespace */
	while (len > 0 && xisspace(*buf))
	    xmemmove(buf, buf + 1, len--);
	if (len == 0) {
	    /* Continue to read... */
	    /* Timeout NOT increased. This whitespace was from previous reply */
	    commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	    return;
	}
    }
    if (len < 0) {
	debug(50, 2) ("httpReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
	if (ignoreErrno(errno)) {
	    commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	} else if (entry->mem_obj->inmem_hi == 0) {
	    ErrorState *err;
	    err = errorCon(ERR_READ_ERROR, HTTP_BAD_GATEWAY);
	    err->request = requestLink((request_t *) request);
	    err->xerrno = errno;
	    fwdFail(httpState->fwd, err);
	    comm_close(fd);
	} else {
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->inmem_hi == 0) {
	ErrorState *err;
	err = errorCon(ERR_ZERO_SIZE_OBJECT, HTTP_BAD_GATEWAY);
	err->xerrno = errno;
	err->request = requestLink((request_t *) request);
	fwdFail(httpState->fwd, err);
	httpState->eof = 1;
	comm_close(fd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	httpState->eof = 1;
#ifdef HS_FEAT_ICAP	    
	if(httpState->icap_writer && cbdataValid(httpState->icap_writer)) {
	     debug(81, 3) ("httpReadReply: EOF for ICAP writer\n");
	     icapSendRespMod(httpState->icap_writer, buf, len, 1);
	}
#endif
	if (httpState->reply_hdr_state < 2)
	    /*
	     * Yes Henrik, there is a point to doing this.  When we
	     * called httpProcessReplyHeader() before, we didn't find
	     * the end of headers, but now we are definately at EOF, so
	     * we want to process the reply headers.
	     */
	    httpProcessReplyHeader(httpState, buf, len);
	if (entry->mem_obj->reply->sline.status == HTTP_HEADER_TOO_LARGE) {
	    ErrorState *err;
	    storeEntryReset(entry);
	    err = errorCon(ERR_TOO_BIG, HTTP_BAD_GATEWAY);
	    err->request = requestLink((request_t *) request);
	    fwdFail(httpState->fwd, err);
	    httpState->fwd->flags.dont_retry = 1;
	} else if (entry->mem_obj->reply->sline.status == HTTP_INVALID_HEADER && !(entry->mem_obj->reply->sline.version.major == 0 && entry->mem_obj->reply->sline.version.minor == 9)) {
	    ErrorState *err;
	    storeEntryReset(entry);
	    err = errorCon(ERR_INVALID_RESP, HTTP_BAD_GATEWAY);
	    err->request = requestLink((request_t *) request);
	    fwdFail(httpState->fwd, err);
	    httpState->fwd->flags.dont_retry = 1;
	} else {
	    fwdComplete(httpState->fwd);
	}
	comm_close(fd);
	return;
    } else {
	if (httpState->reply_hdr_state < 2) {
	    httpProcessReplyHeader(httpState, buf, len);
	    if (httpState->reply_hdr_state == 2) {
		http_status s = entry->mem_obj->reply->sline.status;
		if (s == HTTP_HEADER_TOO_LARGE) {
		    ErrorState *err;
		    debug(11, 1) ("WARNING: %s:%d: HTTP header too large\n", __FILE__, __LINE__);
		    storeEntryReset(entry);
		    err = errorCon(ERR_TOO_BIG, HTTP_BAD_GATEWAY);
		    err->request = requestLink((request_t *) request);
		    fwdFail(httpState->fwd, err);
		    httpState->fwd->flags.dont_retry = 1;
		    comm_close(fd);
		    return;
		}
		if (s == HTTP_INVALID_HEADER && !(entry->mem_obj->reply->sline.version.major == 0 && entry->mem_obj->reply->sline.version.minor == 9)) {
		    ErrorState *err;
		    storeEntryReset(entry);
		    err = errorCon(ERR_INVALID_RESP, HTTP_BAD_GATEWAY);
		    err->request = requestLink((request_t *) request);
		    fwdFail(httpState->fwd, err);
		    httpState->fwd->flags.dont_retry = 1;
		    comm_close(fd);
		    return;
		}
#if WIP_FWD_LOG
		fwdStatus(httpState->fwd, s);
#endif
		/*
		 * If its not a reply that we will re-forward, then
		 * allow the client to get it.
		 */
		if (!fwdReforwardableStatus(s))
		    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
	    }
	}
#ifdef HS_FEAT_ICAP
	if (httpState->icap_writer){
	    debug(81, 5) ("calling icapSendRespMod from %s:%d\n", __FILE__, __LINE__);
	    if (cbdataValid(httpState->icap_writer)) {
		icapSendRespMod(httpState->icap_writer, buf, len, 0);
		httpState->icap_writer->fake_content_length += len;
	    }
	}else
#endif
	    storeAppend(entry, buf, len);


	debug(11, 5) ("httpReadReply: after storeAppend FD %d read %d\n", fd, len);
#if HS_FEAT_ICAP
	if (httpState->icap_writer) {
	     if (!httpState->icap_writer->respmod.entry) {
		  debug(11, 3) ("httpReadReply: FD: %d: icap respmod aborded!\n", fd);
		  comm_close(fd);
		  return;
	     }
	}
	else
#endif
	if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	    /*
	     * the above storeAppend() call could ABORT this entry,
	     * in that case, the server FD should already be closed.
	     * there's nothing for us to do.
	     */
	    return;
	}
	switch (httpPconnTransferDone(httpState)) {
	case 1:
	    {
		int keep_alive = 1;
		/*
		 * If we didn't send a keep-alive request header, then this
		 * can not be a persistent connection.
		 */
		if (!httpState->flags.keepalive)
		    keep_alive = 0;
		/*
		 * If we haven't sent the whole request then this can not be a persistent
		 * connection.
		 */
		if (!httpState->flags.request_sent) {
		    debug(11, 1) ("httpReadReply: Request not yet fully sent \"%s %s\"\n",
			RequestMethodStr[httpState->orig_request->method],
			storeUrl(entry));
		    keep_alive = 0;
		}
		/*
		 * What does the reply have to say about keep-alive?
		 */
		if (!entry->mem_obj->reply->keep_alive)
		    keep_alive = 0;
		/*
		 * Verify that the connection is clean
		 */
		if (len == read_sz) {
		    statCounter.syscalls.sock.reads++;
		    len = FD_READ_METHOD(fd, buf, SQUID_TCP_SO_RCVBUF);
		    if ((len < 0 && !ignoreErrno(errno)) || len == 0) {
			keep_alive = 0;
		    } else if (len > 0) {
			debug(11, Config.onoff.relaxed_header_parser <= 0 || keep_alive ? 1 : 2)
			    ("httpReadReply: Excess data from \"%s %s\"\n",
			    RequestMethodStr[httpState->orig_request->method],
			    storeUrl(entry));
#ifdef HS_FEAT_ICAP
			if (httpState->icap_writer) {
			     debug(81, 5) ("calling icapSendRespMod from %s:%d\n", __FILE__, __LINE__);
			     icapSendRespMod(httpState->icap_writer, buf, len, 0);
			     httpState->icap_writer->fake_content_length += len;
			}else
#endif
			     storeAppend(entry, buf, len);
			keep_alive = 0;
		    }
		}
#ifdef HS_FEAT_ICAP
                if (httpState->icap_writer)
                    icapSendRespMod(httpState->icap_writer, NULL, 0, 1);
#endif
		if (keep_alive) {
		    /* yes we have to clear all these! */
		    commSetDefer(fd, NULL, NULL);
		    commSetTimeout(fd, -1, NULL, NULL);
		    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
#if DELAY_POOLS
		    delayClearNoDelay(fd);
#endif
		    comm_remove_close_handler(fd, httpStateFree, httpState);
		    fwdUnregister(fd, httpState->fwd);
		    pconnPush(fd, request->host, request->port);
		    fwdComplete(httpState->fwd);
		    httpState->fd = -1;
		    httpStateFree(fd, httpState);
		} else {
		    fwdComplete(httpState->fwd);
		    comm_close(fd);
		}
	    }
	    return;
	case 0:
	    /* Wait for more data or EOF condition */
	    if (httpState->flags.keepalive_broken) {
		commSetTimeout(fd, 10, NULL, NULL);
	    } else {
		commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
	    }
	    commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	    return;
	case -1:
	    /* Server is nasty on us. Shut down */
	    debug(11, Config.onoff.relaxed_header_parser <= 0 || entry->mem_obj->reply->keep_alive ? 1 : 2)
		("httpReadReply: Excess data from \"%s %s\"\n",
		RequestMethodStr[httpState->orig_request->method],
		storeUrl(entry));
#ifdef HS_FEAT_ICAP
            if (httpState->icap_writer)
                icapSendRespMod(httpState->icap_writer, NULL, 0, 1);
#endif
	    fwdComplete(httpState->fwd);
	    comm_close(fd);
	    return;
	default:
	    fatal("Unexpected httpPconnTransferDone() status\n");
	    break;
	}
    }
}

#ifdef HS_FEAT_ICAP
static int
httpReadReplyWaitForIcap(int fd, void *data)
{
    HttpStateData *httpState = data;
    if (NULL == httpState->icap_writer)
	return 0;
    /* 
     * Do not defer when we are not connected to the icap server.
     * Defer when the icap server connection is not established but pending
     * Defer when the icap server is busy (writing on the socket)
     */
    debug(11, 5) ("httpReadReplyWaitForIcap: FD %d, connect_requested=%d\n",
	fd, httpState->icap_writer->flags.connect_requested);
    if (!httpState->icap_writer->flags.connect_requested)
      return 0;
    debug(11, 5) ("httpReadReplyWaitForIcap: FD %d, connect_pending=%d\n",
	fd, httpState->icap_writer->flags.connect_pending);
    if (httpState->icap_writer->flags.connect_pending)
	return 1;
    debug(11, 5) ("httpReadReplyWaitForIcap: FD %d, write_pending=%d\n",
	fd, httpState->icap_writer->flags.write_pending);
    if (httpState->icap_writer->flags.write_pending)
	return 1;
    return 0;
}
#endif

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void
httpSendComplete(int fd, char *bufnotused, size_t size, int errflag, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = httpState->entry;
    ErrorState *err;
    debug(11, 5) ("httpSendComplete: FD %d: size %d: errflag %d.\n",
	fd, (int) size, errflag);
#if URL_CHECKSUM_DEBUG
    assert(entry->mem_obj->chksum == url_checksum(entry->mem_obj->url));
#endif
    if (size > 0) {
	fd_bytes(fd, size, FD_WRITE);
	kb_incr(&statCounter.server.all.kbytes_out, size);
	kb_incr(&statCounter.server.http.kbytes_out, size);
    }
    if (errflag == COMM_ERR_CLOSING)
	return;
    if (errflag) {
	if (entry->mem_obj->inmem_hi == 0) {
	    err = errorCon(ERR_WRITE_ERROR, HTTP_BAD_GATEWAY);
	    err->xerrno = errno;
	    err->request = requestLink(httpState->orig_request);
	    errorAppendEntry(entry, err);
	}
	comm_close(fd);
	return;
    } else {
	/* Schedule read reply. */
#ifdef HS_FEAT_ICAP
	if (icapService(ICAP_SERVICE_RESPMOD_PRECACHE, httpState->orig_request)) {
	    httpState->icap_writer = icapRespModStart(
		ICAP_SERVICE_RESPMOD_PRECACHE,
		httpState->orig_request, httpState->entry, httpState->flags);
	    if (-1 == (int) httpState->icap_writer) {
		/* TODO: send error here and exit */
		httpState->icap_writer = 0;
		err = errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
		err->xerrno = errno;
		err->request = requestLink(httpState->orig_request);
		errorAppendEntry(entry, err);
		comm_close(fd);
		return;
	    } else if (httpState->icap_writer) {
		request_flags fake_flags = httpState->orig_request->flags;
		method_t fake_method = entry->mem_obj->method;
		const char *fake_msg = "this is a fake entry for "
		" response sent to an ICAP RESPMOD server";
		cbdataLock(httpState->icap_writer);
		/*
		 * this httpState will give the data it reads to
		 * the icap server, rather than put it into
		 * a StoreEntry
		 */
		storeUnlockObject(httpState->entry);
		storeUnregisterAbort(httpState->entry);
		/*
		 * create a bogus entry because the code assumes one is
		 * always there.
		 */
		fake_flags.cachable = 0;
		fake_flags.hierarchical = 0;	/* force private key */
		httpState->entry = storeCreateEntry("fake", "fake", fake_flags, fake_method);
		storeAppend(httpState->entry, fake_msg, strlen(fake_msg));
		/*
		 * pull a switcheroo on fwdState->entry.
		 */
		storeUnlockObject(httpState->fwd->entry);
		httpState->fwd->entry = httpState->entry;
		storeLockObject(httpState->fwd->entry);
		/*
		 * Note that we leave fwdState connected to httpState,
		 * but we changed the entry.  So when fwdComplete
		 * or whatever is called it does no harm -- its
		 * just the fake entry.
		 */
	    } else {
		/*
		 * failed to open connection to ICAP server. 
		 * But bypass request, so just continue here.
		 */
	    }
	}
#endif
	/*
	 * Set the read timeout here because it hasn't been set yet.
	 * We only set the read timeout after the request has been
	 * fully written to the server-side.  If we start the timeout
	 * after connection establishment, then we are likely to hit
	 * the timeout for POST/PUT requests that have very large
	 * request bodies.
	 */

	/* removed in stable5:
	 * commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	 */
	commSetTimeout(fd, Config.Timeout.read, httpTimeout, httpState);
#ifdef HS_FEAT_ICAP
	if (httpState->icap_writer) {
	    debug(11, 5) ("FD %d, setting httpReadReplyWaitForIcap\n", httpState->fd);
	    commSetDefer(httpState->fd, httpReadReplyWaitForIcap, httpState);
	} else
#endif
	commSetDefer(httpState->fd, fwdCheckDeferRead, entry);
    }
    httpState->flags.request_sent = 1;
}

/*
 * build request headers and append them to a given MemBuf 
 * used by httpBuildRequestPrefix()
 * note: calls httpHeaderInit(), the caller is responsible for Clean()-ing
 */
void
httpBuildRequestHeader(request_t * request,
    request_t * orig_request,
    StoreEntry * entry,
    HttpHeader * hdr_out,
    http_state_flags flags)
{
    /* building buffer for complex strings */
#define BBUF_SZ (MAX_URL+32)
    LOCAL_ARRAY(char, bbuf, BBUF_SZ);
    String strConnection = StringNull;
    const HttpHeader *hdr_in = &orig_request->header;
    int we_do_ranges;
    const HttpHeaderEntry *e;
    String strVia;
    String strFwd;
    HttpHeaderPos pos = HttpHeaderInitPos;
    httpHeaderInit(hdr_out, hoRequest);
    /* append our IMS header */
    if (request->lastmod > -1 && request->method == METHOD_GET)
	httpHeaderPutTime(hdr_out, HDR_IF_MODIFIED_SINCE, request->lastmod);

    /* decide if we want to do Ranges ourselves 
     * (and fetch the whole object now)
     * We want to handle Ranges ourselves iff
     *    - we can actually parse client Range specs
     *    - the specs are expected to be simple enough (e.g. no out-of-order ranges)
     *    - reply will be cachable
     * (If the reply will be uncachable we have to throw it away after 
     *  serving this request, so it is better to forward ranges to 
     *  the server and fetch only the requested content) 
     */
    if (NULL == orig_request->range)
	we_do_ranges = 0;
    else if (!orig_request->flags.cachable)
	we_do_ranges = 0;
    else if (httpHdrRangeOffsetLimit(orig_request->range))
	we_do_ranges = 0;
    else
	we_do_ranges = 1;
    debug(11, 8) ("httpBuildRequestHeader: range specs: %p, cachable: %d; we_do_ranges: %d\n",
	orig_request->range, orig_request->flags.cachable, we_do_ranges);

    strConnection = httpHeaderGetList(hdr_in, HDR_CONNECTION);
    while ((e = httpHeaderGetEntry(hdr_in, &pos))) {
	debug(11, 5) ("httpBuildRequestHeader: %s: %s\n",
	    strBuf(e->name), strBuf(e->value));
	if (!httpRequestHdrAllowed(e, &strConnection)) {
	    debug(11, 2) ("'%s' header denied by anonymize_headers configuration\n",
		strBuf(e->name));
	    continue;
	}
	switch (e->id) {
	case HDR_PROXY_AUTHORIZATION:
	    /* Only pass on proxy authentication to peers for which
	     * authentication forwarding is explicitly enabled
	     */
	    if (request->flags.proxying && orig_request->peer_login &&
		strcmp(orig_request->peer_login, "PASS") == 0) {
		httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	    }
	    break;
	case HDR_AUTHORIZATION:
	    /* Pass on WWW authentication even if used locally. If this is
	     * not wanted in an accelerator then the header can be removed
	     * using the anonymization functions
	     */
	    httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	    /* XXX Some accelerators might want to strip the header
	     * and regard the reply as cacheable, but authentication
	     * is not normally enabled for accelerators without reading
	     * the code, so there is not much use in adding logics here
	     * without first defining the concept of having authentication
	     * in the accelerator...
	     */
	    break;
	case HDR_HOST:
	    /*
	     * Normally Squid rewrites the Host: header.
	     * However, there is one case when we don't: If the URL
	     * went through our redirector and the admin configured
	     * 'redir_rewrites_host' to be off.
	     */
	    if (request->flags.redirected && !Config.onoff.redir_rewrites_host)
		httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	    else {
		/* use port# only if not default */
		if (orig_request->port == urlDefaultPort(orig_request->protocol)) {
		    httpHeaderPutStr(hdr_out, HDR_HOST, orig_request->host);
		} else {
		    httpHeaderPutStrf(hdr_out, HDR_HOST, "%s:%d",
			orig_request->host, (int) orig_request->port);
		}
	    }
	    break;
	case HDR_IF_MODIFIED_SINCE:
	    /* append unless we added our own;
	     * note: at most one client's ims header can pass through */
	    if (!httpHeaderHas(hdr_out, HDR_IF_MODIFIED_SINCE))
		httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	    break;
	case HDR_MAX_FORWARDS:
	    if (orig_request->method == METHOD_TRACE) {
		/* sacrificing efficiency over clarity, etc. */
		const int hops = httpHeaderGetInt(hdr_in, HDR_MAX_FORWARDS);
		if (hops > 0)
		    httpHeaderPutInt(hdr_out, HDR_MAX_FORWARDS, hops - 1);
	    }
	    break;
	case HDR_RANGE:
	case HDR_IF_RANGE:
	case HDR_REQUEST_RANGE:
	    if (!we_do_ranges)
		httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	    break;
	case HDR_PROXY_CONNECTION:
	case HDR_CONNECTION:
	case HDR_VIA:
	case HDR_X_FORWARDED_FOR:
	case HDR_CACHE_CONTROL:
	    /* append these after the loop if needed */
	    break;
	default:
	    /* pass on all other header fields */
	    httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	}
    }

    /* append Via */
    strVia = httpHeaderGetList(hdr_in, HDR_VIA);
    snprintf(bbuf, BBUF_SZ, "%d.%d %s",
	orig_request->http_ver.major,
	orig_request->http_ver.minor, ThisCache);
    strListAdd(&strVia, bbuf, ',');
    httpHeaderPutStr(hdr_out, HDR_VIA, strBuf(strVia));
    stringClean(&strVia);

    /* append X-Forwarded-For */
    strFwd = httpHeaderGetList(hdr_in, HDR_X_FORWARDED_FOR);
    strListAdd(&strFwd,
	(((orig_request->client_addr.s_addr != no_addr.s_addr) && opt_forwarded_for) ?
	    inet_ntoa(orig_request->client_addr) : "unknown"), ',');
    httpHeaderPutStr(hdr_out, HDR_X_FORWARDED_FOR, strBuf(strFwd));
    stringClean(&strFwd);

    /* append Host if not there already */
    if (!httpHeaderHas(hdr_out, HDR_HOST)) {
	/* use port# only if not default */
	if (orig_request->port == urlDefaultPort(orig_request->protocol)) {
	    httpHeaderPutStr(hdr_out, HDR_HOST, orig_request->host);
	} else {
	    httpHeaderPutStrf(hdr_out, HDR_HOST, "%s:%d",
		orig_request->host, (int) orig_request->port);
	}
    }
    /* append Authorization if known in URL, not in header and going direct */
    if (!httpHeaderHas(hdr_out, HDR_AUTHORIZATION)) {
	if (!request->flags.proxying && *request->login) {
	    httpHeaderPutStrf(hdr_out, HDR_AUTHORIZATION, "Basic %s",
		base64_encode(request->login));
	}
    }
    /* append Proxy-Authorization if configured for peer, and proxying */
    if (request->flags.proxying && orig_request->peer_login &&
	!httpHeaderHas(hdr_out, HDR_PROXY_AUTHORIZATION) &&
	strcmp(orig_request->peer_login, "PASS") != 0) {
	if (*orig_request->peer_login == '*') {
	    /* Special mode, to pass the username to the upstream cache */
	    char loginbuf[256];
	    const char *username = "-";
	    if (orig_request->auth_user_request)
		username = authenticateUserRequestUsername(orig_request->auth_user_request);
	    snprintf(loginbuf, sizeof(loginbuf), "%s%s", username, orig_request->peer_login + 1);
	    httpHeaderPutStrf(hdr_out, HDR_PROXY_AUTHORIZATION, "Basic %s",
		base64_encode(loginbuf));
	} else {
	    httpHeaderPutStrf(hdr_out, HDR_PROXY_AUTHORIZATION, "Basic %s",
		base64_encode(orig_request->peer_login));
	}
    }
    /* append Cache-Control, add max-age if not there already */
    {
	HttpHdrCc *cc = httpHeaderGetCc(hdr_in);
	if (!cc)
	    cc = httpHdrCcCreate();
	if (!EBIT_TEST(cc->mask, CC_MAX_AGE)) {
	    const char *url = entry ? storeUrl(entry) : urlCanonical(orig_request);
	    httpHdrCcSetMaxAge(cc, getMaxAge(url));
#ifndef HS_FEAT_ICAP
	    /* Don;t bother - if  the url you want to cache is redirected? */
	    if (strLen(request->urlpath))
		assert(strstr(url, strBuf(request->urlpath)));
#endif
	}
	/* Set no-cache if determined needed but not found */
	if (orig_request->flags.nocache && !httpHeaderHas(hdr_in, HDR_PRAGMA))
	    EBIT_SET(cc->mask, CC_NO_CACHE);
	/* Enforce sibling relations */
	if (flags.only_if_cached)
	    EBIT_SET(cc->mask, CC_ONLY_IF_CACHED);
	httpHeaderPutCc(hdr_out, cc);
	httpHdrCcDestroy(cc);
    }
    /* maybe append Connection: keep-alive */
    if (flags.keepalive) {
	if (flags.proxying) {
	    httpHeaderPutStr(hdr_out, HDR_PROXY_CONNECTION, "keep-alive");
	} else {
	    httpHeaderPutStr(hdr_out, HDR_CONNECTION, "keep-alive");
	}
    }
    /* Now mangle the headers. */
    httpHdrMangleList(hdr_out, orig_request);
    stringClean(&strConnection);
}

/* build request prefix and append it to a given MemBuf; 
 * return the length of the prefix */
int
httpBuildRequestPrefix(request_t * request,
    request_t * orig_request,
    StoreEntry * entry,
    MemBuf * mb,
    http_state_flags flags)
{
    const int offset = mb->size;
    memBufPrintf(mb, "%s %s HTTP/1.0\r\n",
	RequestMethodStr[request->method],
	strLen(request->urlpath) ? strBuf(request->urlpath) : "/");
    /* build and pack headers */
    {
	HttpHeader hdr;
	Packer p;
	httpBuildRequestHeader(request, orig_request, entry, &hdr, flags);
	packerToMemInit(&p, mb);
	httpHeaderPackInto(&hdr, &p);
	httpHeaderClean(&hdr);
	packerClean(&p);
    }
    /* append header terminator */
    memBufAppend(mb, crlf, 2);
    return mb->size - offset;
}
/* This will be called when connect completes. Write request. */
static void
httpSendRequest(HttpStateData * httpState)
{
    MemBuf mb;
    request_t *req = httpState->request;
    StoreEntry *entry = httpState->entry;
    peer *p = httpState->peer;
    CWCB *sendHeaderDone;
    int fd = httpState->fd;

    debug(11, 5) ("httpSendRequest: FD %d: httpState %p.\n", fd, httpState);

    /* Schedule read reply. (but no timeout set until request fully sent) */
    commSetTimeout(fd, Config.Timeout.lifetime, httpTimeout, httpState);
    commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);

    if (httpState->orig_request->body_reader)
	sendHeaderDone = httpSendRequestEntry;
    else
	sendHeaderDone = httpSendComplete;

    if (p != NULL)
	httpState->flags.proxying = 1;
    else
	httpState->flags.proxying = 0;
    /*
     * Is keep-alive okay for all request methods?
     */
    if (!Config.onoff.server_pconns)
	httpState->flags.keepalive = 0;
    else if (p == NULL)
	httpState->flags.keepalive = 1;
    else if (p->stats.n_keepalives_sent < 10)
	httpState->flags.keepalive = 1;
    else if ((double) p->stats.n_keepalives_recv / (double) p->stats.n_keepalives_sent > 0.50)
	httpState->flags.keepalive = 1;
    if (httpState->peer)
	if (neighborType(httpState->peer, httpState->request) == PEER_SIBLING &&
	    !httpState->peer->options.allow_miss)
	    httpState->flags.only_if_cached = 1;
    memBufDefInit(&mb);
    httpBuildRequestPrefix(req,
	httpState->orig_request,
	entry,
	&mb,
	httpState->flags);
    debug(11, 6) ("httpSendRequest: FD %d:\n%s\n", fd, mb.buf);
    comm_write_mbuf(fd, mb, sendHeaderDone, httpState);
}

void
httpStart(FwdState * fwd)
{
    int fd = fwd->server_fd;
    HttpStateData *httpState;
    request_t *proxy_req;
    /* ErrorState *err; */
    request_t *orig_req = fwd->request;
    debug(11, 3) ("httpStart: \"%s %s\"\n",
	RequestMethodStr[orig_req->method],
	storeUrl(fwd->entry));
    httpState = cbdataAlloc(HttpStateData);
    storeLockObject(fwd->entry);
    httpState->fwd = fwd;
    httpState->entry = fwd->entry;
    httpState->fd = fd;
    if (fwd->servers)
	httpState->peer = fwd->servers->peer;	/* might be NULL */
    if (httpState->peer) {
	proxy_req = requestCreate(orig_req->method,
	    PROTO_NONE, storeUrl(httpState->entry));
	xstrncpy(proxy_req->host, httpState->peer->host, SQUIDHOSTNAMELEN);
	proxy_req->port = httpState->peer->http_port;
	proxy_req->flags = orig_req->flags;
	proxy_req->lastmod = orig_req->lastmod;
	httpState->request = requestLink(proxy_req);
	httpState->orig_request = requestLink(orig_req);
	proxy_req->flags.proxying = 1;
	/*
	 * This NEIGHBOR_PROXY_ONLY check probably shouldn't be here.
	 * We might end up getting the object from somewhere else if,
	 * for example, the request to this neighbor fails.
	 */
	if (httpState->peer->options.proxy_only)
	    storeReleaseRequest(httpState->entry);
#if DELAY_POOLS
	assert(delayIsNoDelay(fd) == 0);
	if (httpState->peer->options.no_delay)
	    delaySetNoDelay(fd);
#endif
    } else {
	httpState->request = requestLink(orig_req);
	httpState->orig_request = requestLink(orig_req);
    }
#ifdef HS_FEAT_ICAP
    if (icapService(ICAP_SERVICE_REQMOD_POSTCACHE, httpState->orig_request)) {
	httpState->icap_writer = icapRespModStart(ICAP_SERVICE_REQMOD_POSTCACHE,
	    httpState->orig_request, httpState->entry, httpState->flags);
	if (httpState->icap_writer) {
	    return;
	}
    }
#endif
    /*
     * register the handler to free HTTP state data when the FD closes
     */
    comm_add_close_handler(fd, httpStateFree, httpState);
    statCounter.server.all.requests++;
    statCounter.server.http.requests++;

    httpSendRequest(httpState);
    /*
     * We used to set the read timeout here, but not any more.
     * Now its set in httpSendComplete() after the full request,
     * including request body, has been written to the server.
     */
}

static void
httpSendRequestEntryDone(int fd, void *data)
{
    HttpStateData *httpState = data;
    aclCheck_t ch;
    debug(11, 5) ("httpSendRequestEntryDone: FD %d\n",
	fd);
    memset(&ch, '\0', sizeof(ch));
    ch.request = httpState->request;
    if (!Config.accessList.brokenPosts) {
	debug(11, 5) ("httpSendRequestEntryDone: No brokenPosts list\n");
	httpSendComplete(fd, NULL, 0, 0, data);
    } else if (!aclCheckFast(Config.accessList.brokenPosts, &ch)) {
	debug(11, 5) ("httpSendRequestEntryDone: didn't match brokenPosts\n");
	httpSendComplete(fd, NULL, 0, 0, data);
    } else {
	debug(11, 2) ("httpSendRequestEntryDone: matched brokenPosts\n");
	comm_write(fd, "\r\n", 2, httpSendComplete, data, NULL);
    }
}

static void
httpRequestBodyHandler2(void *data)
{
    HttpStateData *httpState = (HttpStateData *) data;
    char *buf = httpState->body_buf;
    httpState->body_buf = NULL;
    comm_write(httpState->fd, buf, httpState->body_buf_sz, httpSendRequestEntry, data, memFree8K);
}

static void
httpRequestBodyHandler(char *buf, ssize_t size, void *data)
{
    HttpStateData *httpState = (HttpStateData *) data;
    httpState->body_buf = NULL;
    if (size > 0) {
	if (httpState->reply_hdr_state >= 2 && !httpState->flags.abuse_detected) {
	    httpState->flags.abuse_detected = 1;
	    debug(11, 1) ("httpSendRequestEntryDone: Likely proxy abuse detected '%s' -> '%s'\n",
		inet_ntoa(httpState->orig_request->client_addr),
		storeUrl(httpState->entry));
	    if (httpState->entry->mem_obj->reply->sline.status == HTTP_INVALID_HEADER) {
		memFree8K(buf);
		comm_close(httpState->fd);
		return;
	    }
	    httpState->body_buf = buf;
	    httpState->body_buf_sz = size;
	    /* Give response some time to propagate before sending rest
	     * of request in case of error */
	    eventAdd("POST delay on response", httpRequestBodyHandler2, httpState, 2.0, 1);
	    return;
	}
	comm_write(httpState->fd, buf, size, httpSendRequestEntry, data, memFree8K);
    } else if (size == 0) {
	/* End of body */
	memFree8K(buf);
	httpSendRequestEntryDone(httpState->fd, data);
    } else {
	/* Failed to get whole body, probably aborted */
	memFree8K(buf);
	httpSendComplete(httpState->fd, NULL, 0, COMM_ERR_CLOSING, data);
    }
}

static void
httpSendRequestEntry(int fd, char *bufnotused, size_t size, int errflag, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = httpState->entry;
    ErrorState *err;
    debug(11, 5) ("httpSendRequestEntry: FD %d: size %d: errflag %d.\n",
	fd, (int) size, errflag);
    if (size > 0) {
	fd_bytes(fd, size, FD_WRITE);
	kb_incr(&statCounter.server.all.kbytes_out, size);
	kb_incr(&statCounter.server.http.kbytes_out, size);
    }
    if (errflag == COMM_ERR_CLOSING)
	return;
    if (errflag) {
	if (entry->mem_obj->inmem_hi == 0) {
	    err = errorCon(ERR_WRITE_ERROR, HTTP_BAD_GATEWAY);
	    err->xerrno = errno;
	    err->request = requestLink(httpState->orig_request);
	    errorAppendEntry(entry, err);
	}
	comm_close(fd);
	return;
    }
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	comm_close(fd);
	return;
    }
    httpState->body_buf = memAllocate(MEM_8K_BUF);
    requestReadBody(httpState->orig_request, httpState->body_buf, 8192, httpRequestBodyHandler, httpState);
}

void
httpBuildVersion(http_version_t * version, unsigned int major, unsigned int minor)
{
    version->major = major;
    version->minor = minor;
}
