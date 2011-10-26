
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

#include "squid.h"

/*
 * These once-static functions are required to be global for ICAP
 */
PF clientReadRequest;
PF connStateFree;
int clientCheckContentLength(request_t * r);
void clientProcessRequest(clientHttpRequest *);
int clientCachable(clientHttpRequest *);
int clientHierarchical(clientHttpRequest *);
void clientReadBody(request_t * request, char *buf, size_t size,
    CBCB * callback, void *cbdata);
static void icapReqModPassHttpBody(IcapStateData * icap, char *buf, size_t size,
    CBCB * callback, void *cbdata);

static PF icapReqModReadHttpHdrs;
static PF icapReqModReadHttpBody;
static CWCB icapReqModSendBodyChunk;
static CBCB icapReqModBodyHandler;
static BODY_HANDLER icapReqModBodyReader;
static STRCB icapReqModMemBufAppend;

#define EXPECTED_ICAP_HEADER_LEN 256
static const char *crlf = "\r\n";

/*
 * icapExpectedHttpReqHdrSize
 *
 * calculate the size of the HTTP headers that we expect
 * to read from the ICAP server.
 */
static int
icapExpectedHttpReqHdrSize(IcapStateData * icap)
{
    if (icap->enc.req_body > -1 && icap->enc.req_hdr > -1)
	return (icap->enc.req_body - icap->enc.req_hdr);
    if (icap->enc.null_body > -1)
	return icap->enc.null_body;
    fatal("icapExpectedHttpReqHdrSize: unexpected case");
    return 0;
}

/*
 * icapReqModCreateClientState
 *
 * Creates fake client_side data structures so we can use
 * that module to read/parse the HTTP request that we read
 * from the ICAP server.
 */
static clientHttpRequest *
icapReqModCreateClientState(IcapStateData * icap, request_t * request)
{
    clientHttpRequest *http;
    if (!cbdataValid(icap->reqmod.client_cookie)) {
	debug(81, 3) ("Whups, client cookie invalid\n");
	icap->reqmod.client_fd = -1;
	return NULL;
    }
    http = cbdataAlloc(clientHttpRequest);
    /*
     * use our own urlCanonicalClean here, because urlCanonicalClean
     * may strip everything after a question-mark. As http->uri
     * is used when doing a request to a parent proxy, we need the full
     * url here.
     */
    http->uri = xstrdup(urlCanonical(icap->request));
    http->log_uri = xstrndup(http->uri, MAX_URL);
    http->range_iter.boundary = StringNull;
    http->request = requestLink(request ? request : icap->request);
    http->flags.did_icap_reqmod = 1;
    http->start = icap->reqmod.start;
    http->conn = cbdataAlloc(ConnStateData);
    http->conn->fd = icap->reqmod.client_fd;
    http->conn->in.size = 0;
    http->conn->in.buf = NULL;
    http->conn->log_addr = icap->reqmod.log_addr;
    http->conn->chr = http;
    http->icap_reqmod = NULL;
    comm_add_close_handler(http->conn->fd, connStateFree, http->conn);
    return http;
}

/*
 * icapReqModInterpretHttpRequest
 *
 * Interpret an HTTP request that we read from the ICAP server.
 * Create some "fake" clientHttpRequest and ConnStateData structures
 * so we can pass this new request off to the routines in
 * client_side.c.
 */
static void
icapReqModInterpretHttpRequest(IcapStateData * icap, request_t * request)
{
    clientHttpRequest *http = icapReqModCreateClientState(icap, request);
    if (NULL == http)
	return;
    /*
     * bits from clientReadRequest
     */
    request->content_length = httpHeaderGetSize(&request->header,
	HDR_CONTENT_LENGTH);
    if (!urlCheckRequest(request) ||
	httpHeaderHas(&request->header, HDR_TRANSFER_ENCODING)) {
	ErrorState *err;
	err = errorCon(ERR_UNSUP_REQ, HTTP_NOT_IMPLEMENTED);
	err->request = requestLink(request);
	request->flags.proxy_keepalive = 0;
	http->entry =
	    clientCreateStoreEntry(http, request->method, null_request_flags);
	errorAppendEntry(http->entry, err);
	return;
    }
    if (!clientCheckContentLength(request)) {
	ErrorState *err;
	err = errorCon(ERR_INVALID_REQ, HTTP_LENGTH_REQUIRED);
	err->request = requestLink(request);
	http->entry =
	    clientCreateStoreEntry(http, request->method, null_request_flags);
	errorAppendEntry(http->entry, err);
	return;
    }
    /* Do we expect a request-body? */
    if (request->content_length > 0) {
	debug(81, 5) ("handing request bodies in ICAP REQMOD\n");
	if (request->body_reader_data)
        	cbdataUnlock(request->body_reader_data);
	request->body_reader = icapReqModBodyReader;
	request->body_reader_data = icap;	/* XXX cbdataLock? */
	cbdataLock(icap);                      /*Yes sure .....*/
	memBufDefInit(&icap->reqmod.http_entity.buf);
    }
    if (clientCachable(http))
	request->flags.cachable = 1;
    if (clientHierarchical(http))
	request->flags.hierarchical = 1;
    clientProcessRequest(http);
}

/*
 * icapReqModParseHttpError
 *
 * Handle an error when parsing the new HTTP request we read
 * from the ICAP server.
 */
static void
icapReqModParseHttpError(IcapStateData * icap, const char *reason)
{
    debug(81, 1) ("icapReqModParseHttpError: %s\n", reason);
}

/*
 * icapEntryError
 *
 * A wrapper for errorCon() and errorAppendEntry().
 */
static void
icapEntryError(IcapStateData * icap, err_type et, http_status hs, int xerrno)
{
    ErrorState *err;
    clientHttpRequest *http = icapReqModCreateClientState(icap, NULL);
    if (NULL == http)
	return;
    http->entry = clientCreateStoreEntry(http,
	icap->request->method, null_request_flags);
    err = errorCon(et, hs);
    err->xerrno = xerrno;
    err->request = requestLink(icap->request);
    errorAppendEntry(http->entry, err);
}

/*
 * icapReqModParseHttpRequest
 * 
 * Parse the HTTP request that we read from the ICAP server.
 * Creates and fills in the request_t structure.
 */
static void
icapReqModParseHttpRequest(IcapStateData * icap)
{
    char *mstr;
    char *uri;
    char *inbuf;
    char *t;
    char *token;
    char *headers;
    method_t method;
    request_t *request;
    http_version_t http_ver;
    int reqlen = icap->reqmod.hdr_buf.size;
    int hdrlen;

    /*
     * Lazy, make a copy of the buf so I can chop it up with strtok()
     */
    inbuf = xcalloc(reqlen + 1, 1);
    memcpy(inbuf, icap->reqmod.hdr_buf.buf, reqlen);

    if ((mstr = strtok(inbuf, "\t ")) == NULL) {
	debug(81, 1) ("icapReqModParseHttpRequest: Can't get request method\n");
	icapReqModParseHttpError(icap, "error:invalid-request-method");
	xfree(inbuf);
	return;
    }
    method = urlParseMethod(mstr);
    if (method == METHOD_NONE) {
	debug(81, 1) ("icapReqModParseHttpRequest: Unsupported method '%s'\n",
	    mstr);
	icapReqModParseHttpError(icap, "error:unsupported-request-method");
	xfree(inbuf);
	return;
    }
    /* look for URL+HTTP/x.x */
    if ((uri = strtok(NULL, "\n")) == NULL) {
	debug(81, 1) ("icapReqModParseHttpRequest: Missing URI\n");
	icapReqModParseHttpError(icap, "error:missing-url");
	xfree(inbuf);
	return;
    }
    while (xisspace(*uri))
	uri++;
    t = uri + strlen(uri);
    assert(*t == '\0');
    token = NULL;
    while (t > uri) {
	t--;
	if (xisspace(*t) && !strncmp(t + 1, "HTTP/", 5)) {
	    token = t + 1;
	    break;
	}
    }
    while (t > uri && xisspace(*t))
	*(t--) = '\0';
    debug(81, 5) ("icapReqModParseHttpRequest: URI is '%s'\n", uri);
    if (token == NULL) {
	debug(81, 3) ("icapReqModParseHttpRequest: Missing HTTP identifier\n");
	icapReqModParseHttpError(icap, "error:missing-http-ident");
	xfree(inbuf);
	return;
    }
    if (sscanf(token + 5, "%d.%d", &http_ver.major, &http_ver.minor) != 2) {
	debug(81, 3) ("icapReqModParseHttpRequest: Invalid HTTP identifier.\n");
	icapReqModParseHttpError(icap, "error:invalid-http-ident");
	xfree(inbuf);
	return;
    }
    debug(81, 6) ("icapReqModParseHttpRequest: Client HTTP version %d.%d.\n",
	http_ver.major, http_ver.minor);

    headers = strtok(NULL, null_string);
    hdrlen = inbuf + reqlen - headers;

    if ((request = urlParse(method, uri)) == NULL) {
	debug(81, 3) ("Invalid URL: %s at %s:%d\n", uri, __FILE__, __LINE__);
	icapEntryError(icap, ERR_INVALID_URL, HTTP_BAD_REQUEST, 0);
	xfree(inbuf);
	return;
    }
    /* compile headers */
    if (!httpHeaderParse(&request->header, headers, headers + hdrlen)) {
	debug(81, 3) ("Failed to parse HTTP headers for: %s at %s:%d",
	    uri, __FILE__, __LINE__);
	icapEntryError(icap, ERR_INVALID_REQ, HTTP_BAD_REQUEST, 0);
	xfree(inbuf);
	return;
    }
    debug(81,
	3)
	("icapReqModParseHttpRequest: successfully parsed the HTTP request\n");
    request->http_ver = http_ver;
    request->client_addr = icap->request->client_addr;
    request->my_addr = icap->request->my_addr;
    request->my_port = icap->request->my_port;
    request->class = icap->request->class;
    if (icap->request->auth_user_request != NULL) {
	/* Copy authentification info in new request */
	request->auth_user_request = icap->request->auth_user_request;
	authenticateAuthUserRequestLock(request->auth_user_request);
    }
    icapReqModInterpretHttpRequest(icap, request);
    xfree(inbuf);
}

/*
 * icapReqModHandoffRespMod
 *
 * Handles the case where a REQMOD request results in an HTTP REPLY
 * (instead of an ICAP REPLY that contains a new HTTP REQUEST).  We
 * prepare the IcapStateData for passing off to the icap_reqmod
 * code, where we have functions for reading HTTP replies in ICAP
 * messages.
 */
static void
icapReqModHandoffRespMod(IcapStateData * icap)
{
    extern PF icapReadReply;
    clientHttpRequest *http = icapReqModCreateClientState(icap, NULL);
    if (NULL == http)
	return;
    assert(icap->request);

    http->entry = clientCreateStoreEntry(http,
	icap->request->method, icap->request->flags);
    icap->respmod.entry = http->entry;
    storeLockObject(icap->respmod.entry);

    /* icap->http_flags = ? */
    memBufDefInit(&icap->respmod.buffer);
    memBufDefInit(&icap->chunk_buf);
    assert(icap->current_service);
    icapReadReply(icap->icap_fd, icap);
}

/*
 * icapReqModKeepAliveOrClose
 *
 * Called when we are done reading from the ICAP server.
 * Either close the connection or keep it open for a future
 * transaction.
 */
static void
icapReqModKeepAliveOrClose(IcapStateData * icap)
{
    int fd = icap->icap_fd;
    debug(81, 3) ("%s:%d FD %d\n", __FILE__, __LINE__, fd);
    if (fd < 0)
	return;
    if (!icap->flags.keep_alive) {
	debug(81, 3) ("%s:%d keep_alive not set, closing\n", __FILE__,
	    __LINE__);
	comm_close(fd);
	return;
    }
    if (icap->request->content_length < 0) {
	/* no message body */
	debug(81, 3) ("%s:%d no message body\n", __FILE__, __LINE__);
	if (1 != icap->reqmod.hdr_state) {
	    /* didn't get to end of HTTP headers */
	    debug(81, 3) ("%s:%d didnt find end of headers, closing\n",
		__FILE__, __LINE__);
	    comm_close(fd);
	    return;
	}
    } else if (icap->reqmod.http_entity.bytes_read !=
	icap->request->content_length) {
	debug(81, 3) ("%s:%d bytes_read (%" PRINTF_OFF_T ") != content_length (%" PRINTF_OFF_T ")\n",
	    __FILE__, __LINE__, icap->reqmod.http_entity.bytes_read,
	    icap->request->content_length);
	/* an error */
	comm_close(fd);
	return;
    }
    debug(81, 3) ("%s:%d looks good, keeping alive\n", __FILE__, __LINE__);
    commSetDefer(fd, NULL, NULL);
    commSetTimeout(fd, -1, NULL, NULL);
    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
    comm_remove_close_handler(fd, icapStateFree, icap);
    pconnPush(fd, icap->current_service->hostname, icap->current_service->port);
    icap->icap_fd = -1;
    icapStateFree(-1, icap);
}

/*
 * icapReqModReadHttpHdrs
 *
 * Read the HTTP reply from the ICAP server.  Uses the values
 * from the ICAP Encapsulation header to know how many bytes
 * to read.
 */
static void
icapReqModReadHttpHdrs(int fd, void *data)
{
    IcapStateData *icap = data;
    LOCAL_ARRAY(char, tmpbuf, SQUID_TCP_SO_RCVBUF);
    int rl;
    debug(81, 3) ("icapReqModReadHttpHdrs:\n");
    assert(fd == icap->icap_fd);
    assert(icap->enc.req_hdr == 0);
    if (0 == icap->reqmod.hdr_state) {
	int expect = icapExpectedHttpReqHdrSize(icap);
	int so_far = icap->http_header_bytes_read_so_far;
	int needed = expect - so_far;
	debug(81, 3) ("expect=%d\n", expect);
	debug(81, 3) ("so_far=%d\n", so_far);
	debug(81, 3) ("needed=%d\n", needed);
	assert(needed >= 0);
	if (0 == expect) {
	    fatalf("unexpected condition in %s:%d", __FILE__, __LINE__);
	}
	rl = FD_READ_METHOD(fd, tmpbuf, needed);
	debug(81, 3) ("icapReqModReadHttpHdrs: read %d bytes\n", rl);
	if (rl < 0) {
	    fatalf("need to handle read error at %s:%d", __FILE__, __LINE__);
	}
	fd_bytes(fd, rl, FD_READ);
	kb_incr(&statCounter.icap.all.kbytes_in, rl);
	memBufAppend(&icap->reqmod.hdr_buf, tmpbuf, rl);
	icap->http_header_bytes_read_so_far += rl;
	if (rl != needed) {
	    /* still more header data to read */
	    commSetSelect(fd, COMM_SELECT_READ, icapReqModReadHttpHdrs, icap,
		0);
	    return;
	}
	icap->reqmod.hdr_state = 1;
    }
    assert(1 == icap->reqmod.hdr_state);
    debug(81, 3) ("icapReqModReadHttpHdrs: read the entire request headers\n");
    icapReqModParseHttpRequest(icap);
    if (-1 == icap->reqmod.client_fd) {
	/* we detected that the original client_side went away */
	icapReqModKeepAliveOrClose(icap);
    } else if (icap->enc.req_body > -1) {
	icap->chunk_size = 0;
	memBufDefInit(&icap->chunk_buf);
	commSetSelect(fd, COMM_SELECT_READ, icapReqModReadHttpBody, icap, 0);
    } else {
	icapReqModKeepAliveOrClose(icap);
    }
}


/*
 * icapReqModReadIcapPart
 *
 * Read the ICAP reply header.
 */
static void
icapReqModReadIcapPart(int fd, void *data)
{
    IcapStateData *icap = data;
    int version_major, version_minor;
    const char *str_status;
    int x;
    const char *start;
    const char *end;
    int status;
    int isIcap = 0;
    int directResponse = 0;

    debug(81, 5) ("icapReqModReadIcapPart: FD %d httpState = %p\n", fd, data);
    statCounter.syscalls.sock.reads++;

    x = icapReadHeader(fd, icap, &isIcap);
    if (x < 0) {
	/* Did not find a proper ICAP response */
	debug(81, 3) ("ICAP : Error path!\n");
	icapEntryError(icap, ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR,
	    errno);
	comm_close(fd);
	return;
    }
    if (x == 0) {
	/*
	 * Waiting for more headers.  Schedule new read hander, but
	 * don't reset timeout.
	 */
	commSetSelect(fd, COMM_SELECT_READ, icapReqModReadIcapPart, icap, 0);
	return;
    }
    /*
     * Parse the ICAP header
     */
    assert(icap->icap_hdr.size);
    debug(81, 3) ("Read icap header : <%s>\n", icap->icap_hdr.buf);
    if ((status =
	    icapParseStatusLine(icap->icap_hdr.buf, icap->icap_hdr.size,
		&version_major, &version_minor, &str_status)) < 0) {
	debug(81, 1) ("BAD ICAP status line <%s>\n", icap->icap_hdr.buf);
	/* is this correct in case of ICAP protocol error? */
	icapEntryError(icap, ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR,
	    errno);
	comm_close(fd);
	return;
    };
    if (200 != status) {
	debug(81, 1) ("Unsupported status '%d' from ICAP server\n", status);
	icapEntryError(icap, ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR,
	    errno);
	comm_close(fd);
	return;
    }
    icapSetKeepAlive(icap, icap->icap_hdr.buf);
    if (icapFindHeader(icap->icap_hdr.buf, "Encapsulated:", &start, &end)) {
	icapParseEncapsulated(icap, start, end);
    } else {
	debug(81,
	    1)
	    ("WARNING: icapReqModReadIcapPart() did not find 'Encapsulated' header\n");
    }
    if (icap->enc.res_hdr > -1)
	directResponse = 1;
    else if (icap->enc.res_body > -1)
	directResponse = 1;
    else
	directResponse = 0;
    debug(81, 3) ("icapReqModReadIcapPart: directResponse=%d\n",
	directResponse);

    /* Check whether it is a direct reply - if so over to http part */
    if (directResponse) {
	debug(81,
	    3)
	    ("icapReqModReadIcapPart: FD %d, processing HTTP response for REQMOD!\n",
	    fd);
	/* got the reply, no need to come here again */
	icap->flags.wait_for_reply = 0;
	icap->flags.got_reply = 1;
	icapReqModHandoffRespMod(icap);
	return;
    }
    memBufDefInit(&icap->reqmod.hdr_buf);
    commSetSelect(fd, COMM_SELECT_READ, icapReqModReadHttpHdrs, icap, 0);
    return;
}

/*
 * icapSendReqModDone
 *
 * Called after we've sent the ICAP request.  Checks for errors
 * and installs the handler functions for the next step.
 */
static void
icapSendReqModDone(int fd, char *bufnotused, size_t size, int errflag,
    void *data)
{
    IcapStateData *icap = data;

    debug(81, 5) ("icapSendReqModDone: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);
    if (size > 0) {
	fd_bytes(fd, size, FD_WRITE);
	kb_incr(&statCounter.icap.all.kbytes_out, size);
    }
    if (errflag == COMM_ERR_CLOSING)
	return;
    if (errflag) {
	debug(81, 3) ("icapSendReqModDone: unreachable=1, service=%s\n",
	    icap->current_service->uri);
	icapOptSetUnreachable(icap->current_service);
	icapEntryError(icap, ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR,
	    errno);
	comm_close(fd);
	return;
    }
    /* Schedule read reply. */
    commSetSelect(fd, COMM_SELECT_READ, icapReqModReadIcapPart, icap, 0);
    /*
     * Set the read timeout here because it hasn't been set yet.
     * We only set the read timeout after the request has been
     * fully written to the server-side.  If we start the timeout
     * after connection establishment, then we are likely to hit
     * the timeout for POST/PUT requests that have very large
     * request bodies.
     */
    commSetTimeout(fd, Config.Timeout.read, icapConnectTimeout, icap);
}


/*
 * icapSendReqMod
 *
 * Send the ICAP request, including HTTP request, to the ICAP server
 * after connection has been established.
 */
static void
icapSendReqMod(int fd, int status, void *data)
{
    MemBuf mb;
    MemBuf mb_hdr;
    Packer p;
    IcapStateData *icap = data;
    char *client_addr;
    int icap_fd = icap->icap_fd;
    icap_service *service;
    CWCB *theCallback;

    debug(81, 5) ("icapSendReqMod FD %d, status %d\n", fd, status);
    icap->flags.connect_pending = 0;

    if (COMM_OK != status) {
	debug(81, 1) ("Could not connect to ICAP server %s:%d: %s\n",
	    icap->current_service->hostname,
	    icap->current_service->port, xstrerror());
	debug(81, 3) ("icapSendReqMod: unreachable=1, service=%s\n",
	    icap->current_service->uri);
	icapOptSetUnreachable(icap->current_service);
	icapEntryError(icap, ERR_ICAP_FAILURE, HTTP_SERVICE_UNAVAILABLE, errno);
	comm_close(fd);
	return;
    }
    if (icap->request->content_length > 0)
	theCallback = icapReqModSendBodyChunk;
    else
	theCallback = icapSendReqModDone;

    memBufDefInit(&mb);
    memBufDefInit(&mb_hdr);
    memBufPrintf(&mb_hdr, "%s %s HTTP/%d.%d\r\n",
	RequestMethodStr[icap->request->method],
	icap->reqmod.uri,
	icap->request->http_ver.major, icap->request->http_ver.minor);
    packerToMemInit(&p, &mb_hdr);
    httpHeaderPackInto(&icap->request->header, &p);
    packerClean(&p);
    memBufAppend(&mb_hdr, crlf, 2);
    service = icap->current_service;
    assert(service);
    client_addr = inet_ntoa(icap->request->client_addr);

    memBufPrintf(&mb, "REQMOD %s ICAP/1.0\r\n", service->uri);
    memBufPrintf(&mb, "Encapsulated: req-hdr=0");
    /* TODO: Change the offset using 'request' if needed */
    if (icap->request->content_length > 0)
	memBufPrintf(&mb, ", req-body=%d", mb_hdr.size);
    else
	memBufPrintf(&mb, ", null-body=%d", mb_hdr.size);
    memBufAppend(&mb, crlf, 2);
    if (Config.icapcfg.send_client_ip || service->flags.need_x_client_ip)
	memBufPrintf(&mb, "X-Client-IP: %s\r\n", client_addr);
    if ((Config.icapcfg.send_auth_user
	    || service->flags.need_x_authenticated_user)
	&& (icap->request->auth_user_request != NULL))
	icapAddAuthUserHeader(&mb, icap->request->auth_user_request);
    if(service->keep_alive){
	icap->flags.keep_alive = 1;
    }
    else{
	icap->flags.keep_alive=0;
	memBufAppend(&mb, "Connection: close\r\n", 19);
    }
    memBufAppend(&mb, crlf, 2);
    memBufAppend(&mb, mb_hdr.buf, mb_hdr.size);
    memBufClean(&mb_hdr);

    debug(81, 5) ("icapSendReqMod: FD %d writing {%s}\n", icap->icap_fd,
	mb.buf);
    comm_write_mbuf(icap_fd, mb, theCallback, icap);
}

/*
 * icapReqModStart
 *
 * Initiate an ICAP REQMOD transaction.  Create and fill in IcapStateData
 * structure and request a TCP connection to the server.
 */
IcapStateData *
icapReqModStart(icap_service_t type, const char *uri, request_t * request,
    int fd, struct timeval start, struct in_addr log_addr, void *cookie)
{
    IcapStateData *icap = NULL;
    icap_service *service = NULL;

    debug(81, 3) ("icapReqModStart: type=%d\n", (int) type);
    assert(type >= 0 && type < ICAP_SERVICE_MAX);

    service = icapService(type, request);
    if (!service) {
	debug(81, 3) ("icapReqModStart: no service found\n");
	return NULL;		/* no service found */
    }
    switch (type) {
    case ICAP_SERVICE_REQMOD_PRECACHE:
	break;
    default:
	fatalf("icapReqModStart: unsupported service type '%s'\n",
	    icap_service_type_str[type]);
	break;
    }

    if (service->unreachable) {
	if (service->bypass) {
	    debug(81,
		5) ("icapReqModStart: BYPASS because service unreachable: %s\n",
		service->uri);
	    return NULL;
	} else {
	    debug(81,
		5) ("icapReqModStart: ERROR  because service unreachable: %s\n",
		service->uri);
	    return (IcapStateData *) - 1;
	}
    }
    icap = icapAllocate();
    if (!icap) {
	debug(81, 3) ("icapReqModStart: icapAllocate() failed\n");
	return NULL;
    }
    icap->current_service = service;
    icap->preview_size = service->preview;
    icap->reqmod.uri = uri;	/* XXX should be xstrdup? */
    icap->reqmod.start = start;
    icap->reqmod.log_addr = log_addr;
    icap->request = requestLink(request);
    icap->reqmod.hdr_state = 0;
    icap->reqmod.client_fd = fd;
    icap->reqmod.client_cookie = cookie;
    cbdataLock(icap->reqmod.client_cookie);

    if (!icapConnect(icap, icapSendReqMod))
	return NULL;

    statCounter.icap.all.requests++;
    debug(81, 3) ("icapReqModStart: returning %p\n", icap);
    return icap;
}

/*
 * icapReqModSendBodyChunk
 *
 * A "comm_write" callback.  This is called after comm_write() does
 * its job to let us know how things went.  If there are no errors,
 * get another chunk of the body from client_side.
 */
static void
icapReqModSendBodyChunk(int fd, char *bufnotused, size_t size, int errflag,
    void *data)
{
    IcapStateData *icap = data;
    debug(81, 3) ("icapReqModSendBodyChunk: FD %d wrote %d errflag %d.\n",
	fd, (int) size, errflag);
    if (errflag == COMM_ERR_CLOSING)
	return;
    if (errflag) {
	icapEntryError(icap, ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR,
	    errno);
	comm_close(fd);
	return;
    }
    clientReadBody(icap->request,
	memAllocate(MEM_8K_BUF), 8192, icapReqModBodyHandler, icap);
}

/*
 * icapReqModBodyHandler
 *
 * Called after Squid gets a chunk of the request entity from the
 * client side.  The body is chunkified and passed to comm_write.
 * The comm_write callback depends on whether or not this is the
 * last chunk.
 */
static void
icapReqModBodyHandler(char *buf, ssize_t size, void *data)
{
    IcapStateData *icap = data;
    MemBuf mb;
    CWCB *theCallback = icapReqModSendBodyChunk;
    if (size < 0) {
	debug(81, 1) ("icapReqModBodyHandler: %s\n", xstrerror());
	memFree8K(buf);
	return;
    }
    memBufDefInit(&mb);
    debug(81, 3) ("icapReqModBodyHandler: writing chunk size %d\n", size);
    memBufPrintf(&mb, "%x\r\n", size);
    if (size)
	memBufAppend(&mb, buf, size);
    else
	theCallback = icapSendReqModDone;
    memBufAppend(&mb, crlf, 2);
    memFree8K(buf);
    comm_write_mbuf(icap->icap_fd, mb, theCallback, icap);
}

/*
 * icapReqModReadHttpBody
 *
 * The read handler for the client's HTTP connection when reading
 * message bodies.  Called by comm_select().
 */
static void
icapReqModReadHttpBody(int fd, void *data)
{
    IcapStateData *icap = data;
    int len;
    debug(81, 3) ("icapReqModReadHttpBody: FD %d called\n", fd);
    len = memBufRead(fd, &icap->chunk_buf);
    debug(81, 3) ("icapReqModReadHttpBody: read returns %d\n", len);
    if (len < 0) {
	debug(81, 3) ("icapReqModReadHttpBody: FD %d %s\n", fd, xstrerror());
	if (!ignoreErrno(errno))
	    icap->flags.reqmod_http_entity_eof = 1;
    } else if (0 == len) {
	debug(81, 3) ("icapReqModReadHttpBody: FD %d EOF\n", fd);
	icap->flags.reqmod_http_entity_eof = 1;
    } else {
	fd_bytes(fd, len, FD_READ);
	kb_incr(&statCounter.icap.all.kbytes_in, len);
	icap->reqmod.http_entity.bytes_read +=
	    icapParseChunkedBody(icap,
	    icapReqModMemBufAppend, &icap->reqmod.http_entity.buf);
    }
    if (icap->reqmod.http_entity.bytes_read >= icap->request->content_length)
	icap->flags.reqmod_http_entity_eof = 1;

    if (!icap->flags.reqmod_http_entity_eof)
	commSetSelect(fd, COMM_SELECT_READ, icapReqModReadHttpBody, icap, 0);
    /*
     * Notify the other side if it is waiting for data from us
     */
    debug(81, 3) ("%s:%d http_entity.callback=%p\n", __FILE__, __LINE__,
	icap->reqmod.http_entity.callback);
    debug(81, 3) ("%s:%d http_entity.buf.size=%d\n", __FILE__, __LINE__,
	icap->reqmod.http_entity.buf.size);
    if (icap->reqmod.http_entity.callback && icap->reqmod.http_entity.buf.size) {
	icapReqModPassHttpBody(icap,
	    icap->reqmod.http_entity.callback_buf,
	    icap->reqmod.http_entity.callback_bufsize,
	    icap->reqmod.http_entity.callback,
	    icap->reqmod.http_entity.callback_data);
	icap->reqmod.http_entity.callback = NULL;
	cbdataUnlock(icap->reqmod.http_entity.callback_data);

    }
}

/*
 * icapReqModPassHttpBody
 *
 * Called from http.c after request headers have been sent.
 * This function feeds the http.c module chunks of the request
 * body that were stored in the http_entity.buf MemBuf.
 */
static void
icapReqModPassHttpBody(IcapStateData * icap, char *buf, size_t size,
    CBCB * callback, void *cbdata)
{
    debug(81, 3) ("icapReqModPassHttpBody: called\n");
    if (!buf) {
	debug(81, 1) ("icapReqModPassHttpBody: FD %d called with %p, %d, %p (request aborted)\n",
	    icap->icap_fd, buf, (int) size, cbdata);
	comm_close(icap->icap_fd);
	return;
    }
    if (!cbdataValid(cbdata)) {
	debug(81,
	    1)
	    ("icapReqModPassHttpBody: FD %d callback data invalid, closing\n",
	    icap->icap_fd);
	comm_close(icap->icap_fd);	/*It is better to be sure that the connection will be  closed..... */
	/*icapReqModKeepAliveOrClose(icap); */
	return;
    }
    debug(81, 3) ("icapReqModPassHttpBody: entity buf size = %d\n",
	icap->reqmod.http_entity.buf.size);
    if (icap->reqmod.http_entity.buf.size) {
	int copy_sz = icap->reqmod.http_entity.buf.size;
	if (copy_sz > size)
	    copy_sz = size;
	xmemcpy(buf, icap->reqmod.http_entity.buf.buf, copy_sz);
	/* XXX don't let Alex see this ugliness */
	xmemmove(icap->reqmod.http_entity.buf.buf,
	    icap->reqmod.http_entity.buf.buf + copy_sz,
	    icap->reqmod.http_entity.buf.size - copy_sz);
	icap->reqmod.http_entity.buf.size -= copy_sz;
	debug(81, 3) ("icapReqModPassHttpBody: giving %d bytes to other side\n",
	    copy_sz);
	callback(buf, copy_sz, cbdata);
	debug(81, 3) ("icapReqModPassHttpBody: entity buf size now = %d\n",
	    icap->reqmod.http_entity.buf.size);
	return;
    }
    if (icap->flags.reqmod_http_entity_eof) {
	debug(81, 3) ("icapReqModPassHttpBody: signalling EOF\n");
	callback(buf, 0, cbdata);
	icapReqModKeepAliveOrClose(icap);
	return;
    }
    /*
     * We have no data for the other side at this point.  Save all
     * these values and use them when we do have data.
     */
    assert(NULL == icap->reqmod.http_entity.callback);
    icap->reqmod.http_entity.callback = callback;
    icap->reqmod.http_entity.callback_data = cbdata;
    icap->reqmod.http_entity.callback_buf = buf;
    icap->reqmod.http_entity.callback_bufsize = size;
    cbdataLock(icap->reqmod.http_entity.callback_data);
}

/*
 * Body reader handler for use with request->body_reader function
 * Simple a wrapper for icapReqModPassHttpBody function
 */

static void
icapReqModBodyReader(request_t * request, char *buf, size_t size,
    CBCB * callback, void *cbdata)
{
    IcapStateData *icap = request->body_reader_data;
    icapReqModPassHttpBody(icap, buf, size, callback, cbdata);
}

/*
 * icapReqModMemBufAppend
 *
 * stupid wrapper to eliminate compiler warnings
 */
static void
icapReqModMemBufAppend(void *data, const char *buf, ssize_t size)
{
    memBufAppend(data, buf, size);
}
