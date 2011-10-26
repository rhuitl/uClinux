
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

static CWCB icapSendRespModDone;
static PF icapRespModGobble;
extern PF icapReadReply;
static PF icapRespModReadReply;
static int icapReadReply2(IcapStateData * icap);
static void icapReadReply3(IcapStateData * icap);

#define EXPECTED_ICAP_HEADER_LEN 256
const char *crlf = "\r\n";

static void
getICAPRespModString(MemBuf * mb, int o1, int o2, int o3,
    const char *client_addr, IcapStateData * icap, const icap_service * service)
{
    memBufPrintf(mb, "RESPMOD %s ICAP/1.0\r\nEncapsulated:", service->uri);
    if (o1 >= 0)
	memBufPrintf(mb, " req-hdr=%1d", o1);
    if (o2 >= 0)
	memBufPrintf(mb, ", res-hdr=%1d", o2);
    if (o3 >= 0)
	memBufPrintf(mb, ", res-body=%1d", o3);
    else
	memBufPrintf(mb, ", null-body=%1d", -o3);

    memBufPrintf(mb, crlf);
    if (Config.icapcfg.send_client_ip || service->flags.need_x_client_ip) {
	memBufPrintf(mb, "X-Client-IP: %s\r\n", client_addr);
    }
    if ((Config.icapcfg.send_auth_user
	    || service->flags.need_x_authenticated_user)
	&& (icap->request->auth_user_request != NULL)) {
	icapAddAuthUserHeader(mb, icap->request->auth_user_request);
    }
#if NOT_YET_FINISHED
    if (Config.icapcfg.trailers) {
	memBufPrintf(mb, "X-TE: trailers\r\n");
    }
#endif
    if (service->flags.allow_204)
	memBufPrintf(mb, "Allow: 204\r\n");
}

static int
buildRespModHeader(MemBuf * mb, IcapStateData * icap, char *buf,
    ssize_t len, int theEnd)
{
    MemBuf mb_hdr;
    char *client_addr;
    int o2=0;
    int o3=0;
    int hlen;
    int consumed;
    icap_service *service;
    HttpReply *r;

    if (memBufIsNull(&icap->respmod.req_hdr_copy))
	memBufDefInit(&icap->respmod.req_hdr_copy);

    memBufAppend(&icap->respmod.req_hdr_copy, buf, len);

    if (icap->respmod.req_hdr_copy.size > 4 && strncmp(icap->respmod.req_hdr_copy.buf, "HTTP/", 5)) {
	debug(81, 3) ("buildRespModHeader: Non-HTTP-compliant header: '%s'\n", buf);
	/*
	 *Possible we can consider that we did not have http responce headers 
	 *(maybe HTTP 0.9 protocol), lets returning -1...
	 */
	consumed=-1;
	o2=-1;
	memBufDefInit(&mb_hdr);
    }
    else{

        hlen = headersEnd(icap->respmod.req_hdr_copy.buf,
			   icap->respmod.req_hdr_copy.size);
        debug(81, 3) ("buildRespModHeader: headersEnd = %d(%s)\n", hlen,buf);
        if (0 == hlen)
            return 0;

	/*
	 * calc how many bytes from this 'buf' went towards the
	 * reply header.
	 */
	consumed = hlen - (icap->respmod.req_hdr_copy.size - len);
	debug(81, 3) ("buildRespModHeader: consumed = %d\n", consumed);


	/*
	 * now, truncate our req_hdr_copy at the header end.
	 * this 'if' statement might be unncessary?
	 */
	if (hlen < icap->respmod.req_hdr_copy.size)
	     icap->respmod.req_hdr_copy.size = hlen;
	
	/* Copy request header */
	memBufDefInit(&mb_hdr);
	httpBuildRequestPrefix(icap->request, icap->request,
			       icap->respmod.entry, &mb_hdr, icap->http_flags);
	o2 = mb_hdr.size;
    }

    /* Copy response header - Append to request header mbuffer */
    memBufAppend(&mb_hdr,
	icap->respmod.req_hdr_copy.buf, icap->respmod.req_hdr_copy.size);
    o3 = mb_hdr.size;

    service = icap->current_service;
    assert(service);
    client_addr = inet_ntoa(icap->request->client_addr);

    r = httpReplyCreate();
    httpReplyParse(r, icap->respmod.req_hdr_copy.buf,
	icap->respmod.req_hdr_copy.size);
    icap->respmod.res_body_sz = httpReplyBodySize(icap->request->method, r);
    httpReplyDestroy(r);
    if (icap->respmod.res_body_sz)
	getICAPRespModString(mb, 0, o2, o3, client_addr, icap, service);
    else
	getICAPRespModString(mb, 0, o2, -o3, client_addr, icap, service);
    if (Config.icapcfg.preview_enable)
	if (icap->preview_size >= 0) {
	    memBufPrintf(mb, "Preview: %d\r\n", icap->preview_size);
	    icap->flags.preview_done = 0;
	}
    if(service->keep_alive){
	icap->flags.keep_alive = 1;
	memBufAppend(mb, "Connection: keep-alive\r\n", 24);
    }
    else{
	icap->flags.keep_alive = 0;
	memBufAppend(mb, "Connection: close\r\n", 19);
    }
    memBufAppend(mb, crlf, 2);
    memBufAppend(mb, mb_hdr.buf, mb_hdr.size);
    memBufClean(&mb_hdr);


    return consumed;
}


void
icapSendRespMod(IcapStateData * icap, char *buf, int len, int theEnd)
{
    MemBuf mb;
#if ICAP_PREVIEW
    int size;
    const int preview_size = icap->preview_size;
#endif
    debug(81, 5) ("icapSendRespMod: FD %d, len %d, theEnd %d\n",
	icap->icap_fd, len, theEnd);

    if (icap->flags.no_content) {
	/*
	 * ICAP server said there are no modifications to make, so
	 * just append this data to the StoreEntry
	 */
	if (icap->respmod.resp_copy.size) {
	    /*
	     * first copy the data that we already sent to the ICAP server
	     */
	    memBufAppend(&icap->chunk_buf,
		icap->respmod.resp_copy.buf, icap->respmod.resp_copy.size);
	    icap->respmod.resp_copy.size = 0;
	}
	debug(81, 5) ("icapSendRepMod: len=%d theEnd=%d write_pending=%d\n",
	    len, theEnd, icap->flags.write_pending);
	if (len) {
	    /*
	     * also copy any new data from the HTTP side
	     */
	    memBufAppend(&icap->chunk_buf, buf, len);
	}
	(void) icapReadReply2(icap);
	return;
    }
    if (theEnd) {
	if (icap->respmod.res_body_sz)
	    icap->flags.send_zero_chunk = 1;
	icap->flags.http_server_eof = 1;
    }
    /*
     * httpReadReply is going to call us with a chunk and then
     * right away again with an EOF if httpPconnTransferDone() is true.
     * Since the first write is already dispatched, we'll have to 
     * hack this in somehow.
     */
    if (icap->flags.write_pending) {
	debug(81, 3) ("icapSendRespMod: oops, write_pending=1\n");
	assert(theEnd);
	assert(len == 0);
	return;
    }
    if (!cbdataValid(icap)) {
	debug(81, 3) ("icapSendRespMod: failed to establish connection?\n");
	return;
    }
    memBufDefInit(&mb);

#if SUPPORT_ICAP_204 || ICAP_PREVIEW
    /*
     * make a copy of the response in case ICAP server gives us a 204
     */
    /*
     * This piece of code is problematic for 204 responces outside preview.
     * The icap->respmod.resp_copy continues to filled until we had responce
     * If the icap server waits to gets all data before sends its responce 
     * then we are puting all downloading object to the main system memory.
     * My opinion is that 204 responces outside preview must be disabled .....
     * /chtsanti
     */

    if (len && icap->flags.copy_response) {
	 if (memBufIsNull(&icap->respmod.resp_copy))
	      memBufDefInit(&icap->respmod.resp_copy);
	 memBufAppend(&icap->respmod.resp_copy, buf, len);
    }

#endif

    if (icap->sc == 0) {
	/* No data sent yet. Start with headers */
	 if((icap->sc = buildRespModHeader(&mb, icap, buf, len, theEnd))>0){
	      buf += icap->sc;
	      len -= icap->sc;
	 }
	 /*
	  * Then we do not have http responce headers. All data (previous and those in buf)
	  * now are exist to icap->respmod.req_hdr_copy. Lets get them back.......
	  */
	 if(icap->sc <0){
	      memBufAppend(&icap->respmod.buffer,
			   icap->respmod.req_hdr_copy.buf,
			   icap->respmod.req_hdr_copy.size);
	      icap->sc=icap->respmod.req_hdr_copy.size;
	      icap->respmod.req_hdr_copy.size=0;
	      buf=NULL;
	      len=0;
	 }
    }
    if (0 == icap->sc) {
	/* check again; bail if we're not ready to send ICAP/HTTP hdrs */
	debug(81, 5) ("icapSendRespMod: dont have full HTTP response hdrs\n");
	memBufClean(&mb);
	return;
    }
#if ICAP_PREVIEW
    if (preview_size < 0 || !Config.icapcfg.preview_enable)	/* preview feature off */
	icap->flags.preview_done = 1;

    if (!icap->flags.preview_done) {
	/* preview not yet sent */
	if (icap->sc > 0 && icap->respmod.buffer.size <= preview_size
	    && len > 0) {
	    /* Try to collect at least preview_size+1 bytes */
	    /* By collecting one more byte than needed for preview we know best */
	    /* whether we have to send the ieof chunk extension */
	    size = icap->respmod.buffer.size + len;
	    if (size > preview_size + 1)
		size = preview_size + 1;
	    size -= icap->respmod.buffer.size;
	    debug(81,
		3)
		("icapSendRespMod: FD %d: copy %d more bytes to preview buffer.\n",
		icap->icap_fd, size);
	    memBufAppend(&icap->respmod.buffer, buf, size);
	    buf = ((char *) buf) + size;
	    len -= size;
	}
	if (icap->respmod.buffer.size > preview_size || theEnd) {
	    /* we got enough bytes for preview or this is the last call */
	    /* add preview preview now */
	    if (icap->respmod.buffer.size > 0) {
		size = icap->respmod.buffer.size;
		if (size > preview_size)
		    size = preview_size;
		memBufPrintf(&mb, "%x\r\n", size);
		memBufAppend(&mb, icap->respmod.buffer.buf, size);
		memBufAppend(&mb, crlf, 2);
		icap->sc += size;
	    }
	    if (icap->respmod.buffer.size <= preview_size) {
		/* content length is less than preview size+1 */
		if (icap->respmod.res_body_sz)
		    memBufAppend(&mb, "0; ieof\r\n\r\n", 11);
		memBufReset(&icap->respmod.buffer);	/* will now be used for other data */
	    } else {
		char ch;
		memBufAppend(&mb, "0\r\n\r\n", 5);
		/* end of preview, wait for continue or 204 signal */
		/* copy the extra byte and all other data to the icap buffer */
		/* so that it can be handled next time */
		ch = icap->respmod.buffer.buf[preview_size];
		memBufReset(&icap->respmod.buffer);	/* will now be used for other data */
		memBufAppend(&icap->respmod.buffer, &ch, 1);
		debug(81,
		    3)
		    ("icapSendRespMod: FD %d: sending preview and keeping %d bytes in internal buf.\n",
		    icap->icap_fd, len + 1);
		if (len > 0)
		    memBufAppend(&icap->respmod.buffer, buf, len);
	    }
	    icap->flags.preview_done = 1;
	    icap->flags.wait_for_preview_reply = 1;
	}
    } else if (icap->flags.wait_for_preview_reply) {
	/* received new data while waiting for preview response */
	/* add data to internal buffer and send later */
	debug(81,
	    3)
	    ("icapSendRespMod: FD %d: add %d more bytes to internal buf while waiting for preview-response.\n",
	    icap->icap_fd, len);
	if (len > 0)
	    memBufAppend(&icap->respmod.buffer, buf, len);
	/* do not send any data now while waiting for preview response */
	/* but prepare for read more data on the HTTP connection */
	memBufClean(&mb);
	return;
    } else
#endif
    {
	/* after preview completed and ICAP preview response received */
	/* there may still be some data in the buffer */
	if (icap->respmod.buffer.size > 0) {
	    memBufPrintf(&mb, "%x\r\n", icap->respmod.buffer.size);
	    memBufAppend(&mb, icap->respmod.buffer.buf,
		icap->respmod.buffer.size);
	    memBufAppend(&mb, crlf, 2);
	    icap->sc += icap->respmod.buffer.size;
	    memBufReset(&icap->respmod.buffer);
	}
	if (len > 0) {
	    memBufPrintf(&mb, "%x\r\n", len);
	    memBufAppend(&mb, buf, len);
	    memBufAppend(&mb, crlf, 2);
	    icap->sc += len;
	}
	if (icap->flags.send_zero_chunk) {
	    /* send zero end chunk */
	    icap->flags.send_zero_chunk = 0;
	    icap->flags.http_server_eof = 1;
	    memBufAppend(&mb, "0\r\n\r\n", 5);
	}
	/* wait for data coming from ICAP server as soon as we sent something */
	/* but of course only until we got the response header */
	if (!icap->flags.got_reply)
	    icap->flags.wait_for_reply = 1;
    }
    commSetTimeout(icap->icap_fd, -1, NULL, NULL);

    if (!mb.size) {
	memBufClean(&mb);
	return;
    }
    debug(81, 5) ("icapSendRespMod: FD %d writing {%s}\n", icap->icap_fd,
	mb.buf);
    icap->flags.write_pending = 1;
    comm_write_mbuf(icap->icap_fd, mb, icapSendRespModDone, icap);
}

static void
icapRespModReadReply(int fd, void *data)
{
    IcapStateData *icap = data;
    int version_major, version_minor;
    const char *str_status;
    int x;
    int status = 0;
    int isIcap = 0;
    int directResponse = 0;
    ErrorState *err;
    const char *start;
    const char *end;

    debug(81, 5) ("icapRespModReadReply: FD %d data = %p\n", fd, data);
    statCounter.syscalls.sock.reads++;

    x = icapReadHeader(fd, icap, &isIcap);
    if (x < 0) {
	/* Did not find a proper ICAP response */
	debug(81, 3) ("ICAP : Error path!\n");
	err = errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->request = requestLink(icap->request);
	err->xerrno = errno;
	errorAppendEntry(icap->respmod.entry, err);
	comm_close(fd);
	return;
    }
    if (x == 0) {
	/*
	 * Waiting for more headers.  Schedule new read hander, but
	 * don't reset timeout.
	 */
	commSetSelect(fd, COMM_SELECT_READ, icapRespModReadReply, icap, 0);
	return;
    }
    /*
     * Parse the ICAP header
     */
    assert(icap->icap_hdr.size);
    debug(81, 3) ("Parse icap header : <%s>\n", icap->icap_hdr.buf);
    if ((status =
	    icapParseStatusLine(icap->icap_hdr.buf, icap->icap_hdr.size,
		&version_major, &version_minor, &str_status)) < 0) {
	debug(81, 1) ("BAD ICAP status line <%s>\n", icap->icap_hdr.buf);
	/* is this correct in case of ICAP protocol error? */
	err = errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->request = requestLink(icap->request);
	err->xerrno = errno;
	errorAppendEntry(icap->respmod.entry, err);
	comm_close(fd);
	return;
    };
    /*  OK here we have responce. Lets stop filling the 
     *  icap->respmod.resp_copy buffer ....
     */
    icap->flags.copy_response = 0;

    icapSetKeepAlive(icap, icap->icap_hdr.buf);
#if ICAP_PREVIEW
    if (icap->flags.wait_for_preview_reply) {
	if (100 == status) {
	    debug(81, 5) ("icapRespModReadReply: 100 Continue received\n");
	    icap->flags.wait_for_preview_reply = 0;
	    /* if http_server_eof
	     * call again icapSendRespMod to handle data that
	     * was received while waiting for this ICAP response
	     * else let http to call icapSendRespMod when new data arrived
	     */
	    if (icap->flags.http_server_eof)
		icapSendRespMod(icap, NULL, 0, 0);
	    /*
	     * reset the header to send the rest of the preview
	     */
	    if (!memBufIsNull(&icap->icap_hdr))
		memBufReset(&icap->icap_hdr);

	    /*We do n't need it any more .......*/
	    if (!memBufIsNull(&icap->respmod.resp_copy))
		 memBufClean(&icap->respmod.resp_copy);

	    return;
	}
	if (204 == status) {
	    debug(81,
		5) ("icapRespModReadReply: 204 No modification received\n");
	    icap->flags.wait_for_preview_reply = 0;
	}
    }
#endif /*ICAP_PREVIEW */

#if SUPPORT_ICAP_204 || ICAP_PREVIEW
    if (204 == status) {
	debug(81, 3) ("got 204 status from ICAP server\n");
	debug(81, 3) ("setting icap->flags.no_content\n");
	icap->flags.no_content = 1;
	/*
	 * copy the response already written to the ICAP server
	 */
	debug(81, 3) ("copying %d bytes from resp_copy to chunk_buf\n",
	    icap->respmod.resp_copy.size);
	memBufAppend(&icap->chunk_buf,
	    icap->respmod.resp_copy.buf, icap->respmod.resp_copy.size);
	icap->respmod.resp_copy.size = 0;
	if (icapReadReply2(icap) < 0)
	    comm_close(fd);
	/*
	 * XXX ideally want to clean icap->respmod.resp_copy here
	 * XXX ideally want to "close" ICAP server connection here
	 * OK do it....
	 */
	if (!memBufIsNull(&icap->respmod.resp_copy))
	     memBufClean(&icap->respmod.resp_copy);
	return;
    }
#endif
    if (200 != status) {
	debug(81, 1) ("Unsupported status '%d' from ICAP server\n", status);
	/* Did not find a proper ICAP response */
	err = errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->request = requestLink(icap->request);
	err->xerrno = errno;
	errorAppendEntry(icap->respmod.entry, err);
	comm_close(fd);
	return;
    }
    if (icapFindHeader(icap->icap_hdr.buf, "Encapsulated:", &start, &end)) {
	icapParseEncapsulated(icap, start, end);
    } else {
	debug(81,
	    1)
	    ("WARNING: icapRespModReadReply() did not find 'Encapsulated' header\n");
    }
    if (icap->enc.res_hdr > -1)
	directResponse = 1;
    else if (icap->enc.res_body > -1)
	directResponse = 1;
    else
	directResponse = 0;

    /*
     * "directResponse" is the normal case here.  If we don't have
     * a response header or body, it is an error.
     */
    if (!directResponse) {
	/* Did not find a proper ICAP response */
	debug(81, 3) ("ICAP : Error path!\n");
	err = errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->request = requestLink(icap->request);
	err->xerrno = errno;
	errorAppendEntry(icap->respmod.entry, err);
	comm_close(fd);
	return;
    }
    /* got the reply, no need to come here again */
    icap->flags.wait_for_reply = 0;
    icap->flags.got_reply = 1;
    /* Next, gobble any data before the HTTP response starts */
    if (icap->enc.res_hdr > -1)
	icap->bytes_to_gobble = icap->enc.res_hdr;
    commSetSelect(fd, COMM_SELECT_READ, icapRespModGobble, icap, 0);
}


/*
 * Gobble up (read) some bytes until we get to the start of the body
 */
static void
icapRespModGobble(int fd, void *data)
{
    IcapStateData *icap = data;
    int len;
    LOCAL_ARRAY(char, junk, SQUID_TCP_SO_RCVBUF);
    debug(81, 3) ("icapRespModGobble: FD %d gobbling %d bytes\n", fd,
	icap->bytes_to_gobble);
    len = FD_READ_METHOD(fd, junk, icap->bytes_to_gobble);
    debug(81, 3) ("icapRespModGobble: gobbled %d bytes\n", len);
    if (len < 0) {
	/* XXX error */
	abort();
    }
    icap->bytes_to_gobble -= len;
    if (icap->bytes_to_gobble)
	commSetSelect(fd, COMM_SELECT_READ, icapRespModGobble, icap, 0);
    else
	icapReadReply(fd, icap);
}


static void
icapSendRespModDone(int fd, char *bufnotused, size_t size, int errflag,
    void *data)
{
    IcapStateData *icap = data;
    ErrorState *err;

    icap->flags.write_pending = 0;
    debug(81, 5) ("icapSendRespModDone: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);
    if (size > 0) {
	fd_bytes(fd, size, FD_WRITE);
	kb_incr(&statCounter.icap.all.kbytes_out, size);
    }
    if (errflag == COMM_ERR_CLOSING)
	return;
    if (errflag) {
	err = errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->xerrno = errno;
	if (cbdataValid(icap))
	    err->request = requestLink(icap->request);
	storeEntryReset(icap->respmod.entry);
	errorAppendEntry(icap->respmod.entry, err);
	comm_close(fd);
	return;
    }
    if (EBIT_TEST(icap->respmod.entry->flags, ENTRY_ABORTED)) {
        debug(81, 3) ("icapSendRespModDone: Entry Aborded\n");	
	comm_close(fd);
	return;
    }
    if (icap->flags.send_zero_chunk) {
	debug(81,
	    3) ("icapSendRespModDone: I'm supposed to send zero chunk now\n");
	icap->flags.send_zero_chunk = 0;
	icapSendRespMod(icap, NULL, 0, 1);
	return;
    }
    if (icap->flags.wait_for_preview_reply || icap->flags.wait_for_reply) {
	/* Schedule reading the ICAP response */
	debug(81,
	    3)
	    ("icapSendRespModDone: FD %d: commSetSelect on read icapRespModReadReply.\n",
	    fd);
	commSetSelect(fd, COMM_SELECT_READ, icapRespModReadReply, icap, 0);
#if 1
	commSetTimeout(fd, Config.Timeout.read, icapReadTimeout, icap);
#else
	if (icap->flags.wait_for_preview_reply || icap->flags.http_server_eof) {
	    /*
	     * Set the read timeout only after all data has been sent
	     * or we are waiting for a preview response
	     * If the ICAP server does not return any data till all data
	     * has been sent, we are likely to hit the timeout for large
	     * HTTP bodies
	     */
	    commSetTimeout(fd, Config.Timeout.read, icapReadTimeout, icap);
	}
#endif
    }
}

void
icapConnectOver(int fd, int status, void *data)
{
    ErrorState *err;
    IcapStateData *icap = data;
    debug(81, 3) ("icapConnectOver: FD %d, status=%d\n", fd, status);
    icap->flags.connect_pending = 0;
    if (status < 0) {
	err = errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->xerrno = errno;
	err->request = requestLink(icap->request);
	errorAppendEntry(icap->respmod.entry, err);
	comm_close(fd);
	debug(81, 3) ("icapConnectOver: status < 0, unreachable=1\n");
	icapOptSetUnreachable(icap->current_service);
	return;
    }
    commSetSelect(fd, COMM_SELECT_READ, icapRespModReadReply, icap, 0);
}



IcapStateData *
icapRespModStart(icap_service_t type, request_t * request, StoreEntry * entry,
    http_state_flags http_flags)
{
    IcapStateData *icap = NULL;
    CNCB *theCallback = NULL;
    icap_service *service = NULL;

    debug(81, 3) ("icapRespModStart: type=%d\n", (int) type);
    assert(type >= 0 && type < ICAP_SERVICE_MAX);

    service = icapService(type, request);
    if (!service) {
	debug(81, 3) ("icapRespModStart: no service found\n");
	return NULL;		/* no service found */
    }
    if (service->unreachable) {
	if (service->bypass) {
	    debug(81,
		5)
		("icapRespModStart: BYPASS because service unreachable: %s\n",
		service->uri);
	    return NULL;
	} else {
	    debug(81,
		5)
		("icapRespModStart: ERROR  because service unreachable: %s\n",
		service->uri);
	    return (IcapStateData *) - 1;
	}
    }
    switch (type) {
	/* TODO: When we support more than ICAP_SERVICE_RESPMOD_PRECACHE, we needs to change
	 * this switch, because callbacks isn't keep */
    case ICAP_SERVICE_RESPMOD_PRECACHE:
	theCallback = icapConnectOver;
	break;
    default:
	fatalf("icapRespModStart: unsupported service type '%s'\n",
	    icap_service_type_str[type]);
	break;
    }

    icap = icapAllocate();
    if (!icap) {
	debug(81, 3) ("icapRespModStart: icapAllocate() failed\n");
	return NULL;
    }
    icap->request = requestLink(request);
    icap->respmod.entry = entry;
    if (entry)
	storeLockObject(entry);
    icap->http_flags = http_flags;
    memBufDefInit(&icap->respmod.buffer);
    memBufDefInit(&icap->chunk_buf);

    icap->current_service = service;
    icap->preview_size = service->preview;

    /* 
     * Don't create socket to the icap server now, but only for the first
     * packet receive from the http server. This will resolve all timeout
     * between the web server and icap server.
     */
    debug(81, 3) ("icapRespModStart: setting connect_requested to 0\n");
    icap->flags.connect_requested = 0;

    /*
     * make a copy the HTTP response that we send to the ICAP server in
     * case it turns out to be a 204
     */
#ifdef SUPPORT_ICAP_204
    icap->flags.copy_response = 1;
#elif ICAP_PREVIEW
    if(preview_size < 0 || !Config.icapcfg.preview_enable)
	 icap->flags.copy_response = 0;
    else
	 icap->flags.copy_response = 1;
#else
    icap->flags.copy_response = 0;
#endif
    
    statCounter.icap.all.requests++;
    debug(81, 3) ("icapRespModStart: returning %p\n", icap);
    return icap;
}

static int
icapHttpReplyHdrState(IcapStateData * icap)
{
    assert(icap);
    if (NULL == icap->httpState)
	return 0;
    return icap->httpState->reply_hdr_state;
}

static void
icapProcessHttpReplyHeader(IcapStateData * icap, const char *buf, int size)
{
    if (NULL == icap->httpState) {
	icap->httpState = cbdataAlloc(HttpStateData);
	icap->httpState->request = requestLink(icap->request);
	icap->httpState->orig_request = requestLink(icap->request);
	icap->httpState->entry = icap->respmod.entry;
	storeLockObject(icap->httpState->entry);	/* lock it */
    }
    httpProcessReplyHeader(icap->httpState, buf, size);
    if (2 == icap->httpState->reply_hdr_state)
	EBIT_CLR(icap->httpState->entry->flags, ENTRY_FWD_HDR_WAIT);
}

/*
 * icapRespModKeepAliveOrClose
 *
 * Called when we are done reading from the ICAP server.
 * Either close the connection or keep it open for a future
 * transaction.
 */
static void
icapRespModKeepAliveOrClose(IcapStateData * icap)
{
    int fd = icap->icap_fd;
    if (fd < 0)
	return;
    if (!icap->flags.keep_alive) {
	debug(81, 3) ("%s:%d keep_alive not set, closing\n", __FILE__,
	    __LINE__);
	comm_close(fd);
	return;
    }
    debug(81, 3) ("%s:%d FD %d looks good, keeping alive\n", __FILE__, __LINE__,
	fd);
    commSetDefer(fd, NULL, NULL);
    commSetTimeout(fd, -1, NULL, NULL);
    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
    comm_remove_close_handler(fd, icapStateFree, icap);
    pconnPush(fd, icap->current_service->hostname, icap->current_service->port);
    icap->icap_fd = -1;
    icapStateFree(-1, icap);
}



/*
 * copied from httpPconnTransferDone
 *
 */
static int
icapPconnTransferDone(int fd, IcapStateData * icap)
{
    debug(81, 3) ("icapPconnTransferDone: FD %d\n", fd);
    /*
     * Be careful with 204 responses.  Normally we are done when we
     * see the zero-end chunk, but that won't happen for 204s, so we
     * use an EOF indicator on the HTTP side instead.
     */
    if (icap->flags.no_content && icap->flags.http_server_eof) {
	debug(81, 5) ("icapPconnTransferDone: no content, ret 1\n");
	return 1;
    }
    if (icapHttpReplyHdrState(icap) != 2) {
	debug(81,
	    5) ("icapPconnTransferDone: didn't see end of HTTP hdrs, ret 0\n");
	return 0;
    }
    if (icap->enc.null_body > -1) {
	debug(81, 5) ("icapPconnTransferDone: no message body, ret 1\n");
	return 1;
    }
    if (icap->chunk_size == -2) {	//AI: was != -2 ; and change content with bottom
	/* zero end chunk reached */
	debug(81, 5) ("icapPconnTransferDone: got zero end chunk\n");
	return 1;
    }

    debug(81, 5) ("icapPconnTransferDone: didnt get zero end chunk yet\n");	//AI: change with second top condition

    return 0;
}

static int
icapExpectedHttpReplyHdrSize(IcapStateData * icap)
{
    if (icap->enc.res_body > -1 && icap->enc.res_hdr > -1)
	return (icap->enc.res_body - icap->enc.res_hdr);
    if (icap->enc.null_body > -1 && icap->enc.res_hdr > -1)
	return icap->enc.null_body - icap->enc.res_hdr;
    /*The case we did not get res_hdr .....*/
    if(icap->enc.res_body > -1 )
	 return icap->enc.res_body;
    if (icap->enc.null_body > -1)
	return icap->enc.null_body;
    return -1;
}

/*
 * copied from httpReadReply()
 *
 * by the time this is called, the ICAP headers have already
 * been read.
 */
void
icapReadReply(int fd, void *data)
{
    IcapStateData *icap = data;
    StoreEntry *entry = icap->respmod.entry;
    const request_t *request = icap->request;
    int len;
    debug(81, 5) ("icapReadReply: FD %d: icap %p.\n", fd, data);
    if (icap->flags.no_content && !icap->flags.http_server_eof) {	//AI

	return;
    }
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	comm_close(fd);
	return;
    }
    errno = 0;
    statCounter.syscalls.sock.reads++;
    len = memBufRead(fd, &icap->chunk_buf);
    debug(81, 5) ("icapReadReply: FD %d: len %d.\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
	kb_incr(&statCounter.icap.all.kbytes_in, len);
	commSetTimeout(fd, Config.Timeout.read, icapReadTimeout, icap);
	if (icap->chunk_buf.size < icap->chunk_buf.capacity) {
	    *(icap->chunk_buf.buf + icap->chunk_buf.size) = '\0';
	    debug(81, 9) ("{%s}\n", icap->chunk_buf.buf);
	}
    }
    if (len <= 0) {
	debug(81, 2) ("icapReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
	if (ignoreErrno(errno)) {
	    debug(81, 2) ("icapReadReply: FD %d: ignored errno\n", fd);
	    commSetSelect(fd, COMM_SELECT_READ, icapReadReply, icap, 0);
	} else if (entry->mem_obj->inmem_hi == 0) {
	    ErrorState *err;
	    debug(81, 2) ("icapReadReply: FD %d: generating error page\n", fd);
	    err = errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	    err->request = requestLink((request_t *) request);
	    err->xerrno = errno;
	    errorAppendEntry(entry, err);
	    comm_close(fd);
	} else {
	    debug(81, 2) ("icapReadReply: FD %d: just calling comm_close()\n",
		fd);
	    comm_close(fd);
	}
	return;
    }
    if (icapReadReply2(icap) < 0)
	comm_close(fd);
}

static int
icapReadReply2(IcapStateData * icap)
{
    StoreEntry *entry = icap->respmod.entry;
    const request_t *request = icap->request;
    debug(81, 3) ("icapReadReply2\n");
    if (icap->chunk_buf.size == 0 && entry->mem_obj->inmem_hi == 0) {
	ErrorState *err;
	err = errorCon(ERR_ZERO_SIZE_OBJECT, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->request = requestLink((request_t *) request);
	errorAppendEntry(entry, err);
	icap->flags.http_server_eof = 1;
	return -1;
    }
    if (icap->chunk_buf.size == 0) {
	/* Retrieval done. */
	if (icapHttpReplyHdrState(icap) < 2)
	    icapProcessHttpReplyHeader(icap, icap->chunk_buf.buf,
		icap->chunk_buf.size);
	icap->flags.http_server_eof = 1;
	icapReadReply3(icap);
	return 0;
    }
    if (icapHttpReplyHdrState(icap) == 0) {
	int expect = icapExpectedHttpReplyHdrSize(icap);
	int so_far = icap->http_header_bytes_read_so_far;
	int needed = expect - so_far;
	debug(81, 3) ("expect=%d\n", expect);
	debug(81, 3) ("so_far=%d\n", so_far);
	debug(81, 3) ("needed=%d\n", needed);
	assert(needed < 0 || needed >= 0);
	if (0 > expect) {
	    icapProcessHttpReplyHeader(icap,
		icap->chunk_buf.buf, icap->chunk_buf.size);
	} else if (0 == expect) {
	    /*
	     * this icap reply doesn't give us new HTTP headers
	     * so we must copy them from our copy
	     */
	    debug(81, 1) ("WARNING: untested code at %s:%d\n", __FILE__,
		__LINE__);
	    if(icap->respmod.req_hdr_copy.size){/*For HTTP 0.9 we do not have headers*/
		 storeAppend(entry,
			     icap->respmod.req_hdr_copy.buf,
			     icap->respmod.req_hdr_copy.size);
	    }
	    icapProcessHttpReplyHeader(icap, icap->chunk_buf.buf,
				       icap->chunk_buf.size);
	    assert(icapHttpReplyHdrState(icap) == 2);
	    icap->chunk_size = 0;/*we are ready to read chunks of data now....*/
	} else if (needed) {
	    icapProcessHttpReplyHeader(icap,
		icap->chunk_buf.buf, icap->chunk_buf.size);
	    if (icap->chunk_buf.size >= needed) {
		storeAppend(entry, icap->chunk_buf.buf, needed);
		so_far += needed;
		xmemmove(icap->chunk_buf.buf,
		    icap->chunk_buf.buf + needed,
		    icap->chunk_buf.size - needed);
		icap->chunk_buf.size -= needed;
		assert(icapHttpReplyHdrState(icap) == 2);
		icap->chunk_size = 0;
	    } else {
		/*
		 * We don't have the full HTTP reply headers yet, so keep
		 * the partial reply buffered in 'chunk_buf' and wait
		 * for more.
		 */
                debug(81,3)("We don't have full Http headers.Schedule a new read\n");
  		commSetSelect(icap->icap_fd, COMM_SELECT_READ, icapReadReply, icap, 0);
	    }
	}
	icap->http_header_bytes_read_so_far = so_far;
    }
    debug(81, 3) ("%s:%d: icap->chunk_buf.size=%d\n", __FILE__, __LINE__,
	(int) icap->chunk_buf.size);
    debug(81, 3) ("%s:%d: flags.no_content=%d\n", __FILE__, __LINE__,
	icap->flags.no_content);
    if (icap->flags.no_content) {
	/* data from http.c is not chunked */
	if (!EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	    debug(81, 3) ("copying %d bytes from chunk_buf to entry\n",
		icap->chunk_buf.size);
	    storeAppend(entry, icap->chunk_buf.buf, icap->chunk_buf.size);
	    icap->chunk_buf.size = 0;
	}
    } else if (2 == icapHttpReplyHdrState(icap)) {
	if (icap->chunk_buf.size)
	    icapParseChunkedBody(icap, (STRCB *) storeAppend, entry);
    }
    icapReadReply3(icap);
    return 0;
}

static void
icapReadReply3(IcapStateData * icap)
{
    StoreEntry *entry = icap->respmod.entry;
    int fd = icap->icap_fd;
    debug(81, 3) ("icapReadReply3\n");
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	debug(81, 3) ("icapReadReply3: Entry Aborded\n");
	comm_close(fd);
    } else if (icapPconnTransferDone(fd, icap)) {
	storeComplete(entry);
	icapRespModKeepAliveOrClose(icap);
    } else if (!icap->flags.no_content) {
	/* Wait for EOF condition */
	commSetSelect(fd, COMM_SELECT_READ, icapReadReply, icap, 0);
	debug(81,
	    3)
	    ("icapReadReply3: Going to read mode data throught icapReadReply\n");
    } else {
	debug(81, 3) ("icapReadReply3: Nothing\n");
    }
}
