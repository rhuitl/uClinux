///
///	@file 	request.cpp
/// @brief 	Request class to handle individual HTTP requests.
///
///	The Request class is the real work-horse in managing HTTP requests. An
///	instance is created per HTTP request. During keep-alive it is preserved to
///	process further requests.
///
///	@remarks Requests run in a single thread and do not need multi-thread 
///	locking except for the timeout code which may run on another thread.
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	The latest version of this code is available at http://www.mbedthis.com
//
//	This software is open source; you can redistribute it and/or modify it 
//	under the terms of the GNU General Public License as published by the 
//	Free Software Foundation; either version 2 of the License, or (at your 
//	option) any later version.
//
//	This program is distributed WITHOUT ANY WARRANTY; without even the 
//	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
//	See the GNU General Public License for more details at:
//	http://www.mbedthis.com/downloads/gplLicense.html
//	
//	This General Public License does NOT permit incorporating this software 
//	into proprietary programs. If you are unable to comply with the GPL, a 
//	commercial license for this software and support services are available
//	from Mbedthis Software at http://www.mbedthis.com
//
////////////////////////////////// Includes ////////////////////////////////////

#include	"http.h"

////////////////////////////// Forward Declarations ////////////////////////////

static void	socketEventWrapper(void *data, MprSocket *sock, int mask, 
	int isPool);
static void	timeoutWrapper(void *arg, MprTimer *tp);
static int	refillDoc(MprBuf *bp, void *arg);

//////////////////////////////////// Code //////////////////////////////////////
//
//	Requests are only ever instantiated from acceptWrapper in server.cpp which
//	is only ever called by select/task. So these are serialized by select.
//

MaRequest::MaRequest(MaHostAddress *ap, MaHost *hp)
{
	memset((void*) &stats, 0, sizeof(stats));
	memset((void*) &fileInfo, 0, sizeof(fileInfo));

	address = ap;
	host = hp;

#if BLD_FEATURE_LOG
	tMod = new MprLogModule("request");
	mprLog(6, tMod, "New Request, this %x\n", this);
#endif

	bytesWritten = 0;
	env = new MprHashTable(67);
	currentHandler = 0;
	contentLength = -1;
	contentLengthStr[0] = '\0';
	decodedQuery = 0;
	dir = 0;
	etag = 0;
	extraPath = 0;
	file = 0;
	fileName = 0;
	fileSystem = host->server->getFileSystem();
	flags = 0;
	group = 0;
	inUse = 0;
	lastModified = 0;
	limits = host->getLimits();
	listenSock = 0;
	localPort[0] = '\0';
	location = 0;
	methodFlags = 0;
	requestMimeType = 0;
	responseMimeType = 0;
	responseHeaders = new MprStringList();
	password = 0;
	remainingContent = -1;
	remoteIpAddr = 0;
	remotePort = -1;
	responseCode = 200;
	scriptName = 0;
	scriptEngine = 0;
	sock = 0;
	socketEventMask = 0;
	state = MPR_HTTP_START;
	terminalHandler = 0;
	timer = 0;
	timeout = INT_MAX;
	timestamp = 0;
	uri = 0;
	user = 0;

#if BLD_FEATURE_SESSION
	session = 0;
	sessionId = 0;
#endif

	//
	//	Input Buffer (for headers and post data). NOTE: We rely on the fact 
	//	that we will never wrap the buffer pointers (it is normally a ring).
	//
	inBuf = new MprBuf(MPR_HTTP_IN_BUFSIZE, MPR_HTTP_IN_BUFSIZE);

	//
	//	Output data streams
	//
	hdrBuf = new MaDataStream("hdr", MPR_HTTP_BUFSIZE, limits->maxHeader);
	dynBuf = new MaDataStream("dyn", MPR_HTTP_BUFSIZE, limits->maxResponseBody);
	docBuf = new MaDataStream("doc", MPR_HTTP_DOC_BUFSIZE,MPR_HTTP_DOC_BUFSIZE);
	writeBuf = dynBuf;

	docBuf->buf.setRefillProc(refillDoc, this);
	outputStreams.insert(hdrBuf);

#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Called from the socket callback
//

MaRequest::~MaRequest()
{
	MaDataStream	*dp, *nextDp;

	mprLog(6, tMod, "~Request\n");

	dp = (MaDataStream*) outputStreams.getFirst();
	while (dp) {
		nextDp = (MaDataStream*) outputStreams.getNext(dp);
		outputStreams.remove(dp);
		dp = nextDp;
	}

	delete file;
	delete inBuf;
	delete hdrBuf;
	delete dynBuf;
	delete docBuf;

	mprFree(decodedQuery);
	mprFree(etag);
	mprFree(extraPath);
	mprFree(fileName);
	mprFree(group);
	mprFree(password);
	mprFree(remoteIpAddr);
	mprFree(responseMimeType);
	mprFree(scriptName);
	mprFree(uri);
	mprFree(user);

	if (timer) {
		timer->stop(MPR_TIMEOUT_STOP);
		timer->dispose();
		timer = 0;
	}
	if (env) {
		delete env;
	}
	if (responseHeaders) {
		delete responseHeaders;
	}
	if (sock) {
		sock->dispose();
	}

#if BLD_FEATURE_SESSION
	if (sessionId) {
		mprFree(sessionId);
	}
#endif
#if BLD_FEATURE_LOG
	delete tMod;
#endif
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	For keep-alive we need to be able to service many requests on a single
//	request object
//

void MaRequest::reset()
{
	MaHandler		*hp, *nextHp;
	MaDataStream	*dp, *nextDp;

	mprLog(8, tMod, "reset\n");

	memset((void*) &fileInfo, 0, sizeof(fileInfo));

	if (timer) {
		timer->stop(MPR_TIMEOUT_STOP);
		timer->dispose();
		timer = 0;
	}
	if (etag) {
		mprFree(etag);
		etag = 0;
	}
	if (uri) {
		mprFree(uri);
		uri = 0;
	}
	if (fileName) {
		mprFree(fileName);
		fileName = 0;
	}
	if (decodedQuery) {
		mprFree(decodedQuery);
		decodedQuery = 0;
	}
	if (password) {
		mprFree(password);
		password = 0;
	}
	if (group) {
		mprFree(group);
		group = 0;
	}
	if (user) {
		mprFree(user);
		user = 0;
	}
	if (file) {
		delete file;
		file = 0;
	}
	contentLength = -1;
	remainingContent = -1;

#if BLD_FEATURE_SESSION
	session = 0;
	mprFree(sessionId);
	sessionId = 0;
#endif

	//
	//	NOTE: requestMimeType is not malloced
	//
	requestMimeType = 0;

	if (responseMimeType) {
		mprFree(responseMimeType);
		responseMimeType = 0;
	}

	flags &= (MPR_HTTP_KEEP_ALIVE | MPR_HTTP_SOCKET_EVENT);
	methodFlags = 0;
	state = MPR_HTTP_START;
	responseCode = 200;
	bytesWritten = 0;
	dir = 0;
	location = 0;
	scriptEngine = 0;
	terminalHandler = 0;

	if (responseHeaders) {
		delete responseHeaders;
	}
	responseHeaders = new MprStringList();

	if (env) {
		delete env;
	}
	env = new MprHashTable(67);

	hdrBuf->buf.flush();
	hdrBuf->setSize(0);
	dynBuf->buf.flush();
	dynBuf->setSize(0);
	docBuf->buf.flush();
	docBuf->setSize(0);

	header.reset();

	dp = (MaDataStream*) outputStreams.getFirst();
	while (dp) {
		nextDp = (MaDataStream*) outputStreams.getNext(dp);
		outputStreams.remove(dp);
		dp = nextDp;
	}
	outputStreams.insert(hdrBuf);

	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		nextHp = (MaHandler*) handlers.getNext(hp);
		handlers.remove(hp);
		hp = nextHp;
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Serialized. Called from select. Return 0 if event is a success
//

int MaRequest::acceptEvent(void *data, MprSocket *s, char *ip, int portNum, 
		MprSocket *lp, int isPoolThread)
{
	int		timeout;

	mprAssert(s);
	mprAssert(lp);
	mprAssert(ip);
	mprAssert(portNum >= 0);

	remotePort = portNum;
	remoteIpAddr = mprStrdup(ip);
	listenSock = lp;
	sock = s;
	flags &= ~MPR_HTTP_REUSE;

#if SECURITY_FLAW
	//
	//	WARNING -- IP addresses can be spoofed!!! Enable this code at your own
	//	risk. There is no secure way to identify the source of a user based 
	//	solely on IP address. A better approach is to create a virtual host
	//	that accepts traffic from the loop-back port (127.0.0.1) and then to
	//	also require digest authentication for that virtual host. 
	//
	if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, lp->getIpAddr()) == 0) {
		flags |= MPR_HTTP_LOCAL_REQUEST;
	}
#endif
#if BLD_FEATURE_KEEP_ALIVE
	remainingKeepAlive = host->getMaxKeepAlive();
#endif

	//
	//	If using a named virtual host, we will be running on the default hosts
	//	timeouts
	//
	timeout = host->getTimeout();
	if (timeout > 0) {
		if (!mprGetDebugMode()) {
			mprAssert(timer == 0);
			timeout = host->getTimeout();
			timer = new MprTimer(MPR_HTTP_TIMER_PERIOD, timeoutWrapper, 
				(void*) this);
		}
	}
	if (limits->sendBufferSize > 0) {
		sock->setBufSize(limits->sendBufferSize, -1);
	}

#if BLD_FEATURE_MULTITHREAD
	if (isPoolThread) {
		//
		//	Go into blocking mode and generate a psudo read event
		//
#if FUTURE
		//
		//	This has DOS issues as we are not yet doing timed-reads
		//
		sock->setBlockingMode(1);
		flags |= MPR_HTTP_BLOCKING;
		return socketEventWrapper((void*)this, sock, MPR_READABLE, 
			isPoolThread);
#endif
	}
#endif

	enableReadEvents(1);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

static void socketEventWrapper(void *data, MprSocket *sock, int mask, 
	int isPool)
{
	MaRequest	*rq;
	int			moreData, loopCount;

	rq = (MaRequest*) data;

	mprLog(7, "%d: socketEvent enter with mask %x\n", sock->getFd(), mask);

	rq->lock();
	rq->setFlags(MPR_HTTP_SOCKET_EVENT, ~0);

	if (mask & MPR_WRITEABLE) {
		loopCount = 25;
		do {
			moreData = rq->writeEvent(MPR_HTTP_CLOSE);
		} while (moreData > 0 && (isPool || loopCount-- > 0));
	} 
	if (mask & MPR_READABLE) {
		loopCount = 25;
		do {
			moreData = rq->readEvent();
		} while (moreData > 0 && rq->getState() != MPR_HTTP_RUNNING && 
			(isPool || loopCount-- > 0));
	}

	rq->setFlags(0, ~MPR_HTTP_SOCKET_EVENT);

	//
	//	This will unlock and if instructed above, may actually delete the 
	//	request.
	//
	rq->unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return TRUE if there is more to be done on this socket and to cause
//	this function to be recalled to process more data.
//

int MaRequest::readEvent()
{
	int		nbytes, len;

	if (remainingContent > 0) {
		len = inBuf->getLinearSpace();
		len = (remainingContent > len) ? len : remainingContent;

	} else {
		if (inBuf->getStart() > inBuf->getBuf()) {
			inBuf->copyDown();
			stats.copyDown++;
		}
		len = inBuf->getLinearSpace();
	}

	//	
	//	Len must be non-zero because if our last read filled the buffer, then
	//	one of the actions below must have either depleted the buffer or 
	//	completed the request.
	//
	mprAssert(len > 0);

	//
	//	Read as much as we can
	//
	nbytes = sock->read(inBuf->getEnd(), len);

	mprLog(6, tMod, "%d: readEvent: nbytes %d, eof %d\n", getFd(), 
		nbytes, sock->getEof());

	if (nbytes < 0) {						// Disconnect
		if (state > MPR_HTTP_START && state < MPR_HTTP_DONE) {
			flags |= MPR_HTTP_INCOMPLETE;
			responseCode = MPR_HTTP_COMMS_ERROR;
		} else {
			closeSocket();		// MOB finishRequest(MPR_HTTP_CLOSE);
		}
		return -1;
		
	} else if (nbytes == 0) {
		if (sock->getEof()) {
			mprLog(6, tMod, "%d: readEvent: EOF\n", getFd());
			if (flags & MPR_HTTP_CONTENT_DATA && remainingContent > 0) {
				if (state & MPR_HTTP_RUNNING) {
					terminalHandler->postData(this, 0, -1);
					if (state != MPR_HTTP_DONE) {
						finishRequest(MPR_HTTP_CLOSE);
					}
				}

			} else {
				if (state > MPR_HTTP_START && state < MPR_HTTP_DONE) {
					flags |= MPR_HTTP_INCOMPLETE;
					responseCode = MPR_HTTP_COMMS_ERROR;
					finishRequest(MPR_HTTP_CLOSE);
				} else {
					closeSocket();
				}
			}
		} else {
			;								// No data available currently
		}
		return 0;

	} else {								// Good data
		inBuf->adjustEnd(nbytes);
		inBuf->addNull();
		processRequest();
		return (flags & MPR_HTTP_CONN_CLOSED) ? 0 : 1;
	}
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::processRequest()
{
	char	*line, *cp, *end;
	int		nbytes;

	mprLog(6, tMod, "%d: processRequest, state %d, inBuf len %d\n", 
		getFd(), state, inBuf->getLength());

	setTimeMark();

	while (state < MPR_HTTP_DONE && inBuf->getLength() > 0) {

		//
		//	Don't process data if we are running handlers and there is no
		//	content data. Otherwise we will eat the next request.
		//
		if (contentLength == 0 && state >= MPR_HTTP_RUN_HANDLERS) {
			break;
		}

		line = inBuf->getStart();

		if (flags & MPR_HTTP_CONTENT_DATA) {
			mprAssert(remainingContent > 0);
			nbytes = min(remainingContent, inBuf->getLength());
			mprAssert(nbytes > 0);

			if (flags & MPR_HTTP_PULL_POST) {
				enableReadEvents(0);
			} else {
				mprLog(5, tMod, 
					"%d: processRequest: contentData %d bytes, remaining %d\n", 
					getFd(), nbytes, remainingContent - nbytes);

				mprAssert(terminalHandler);
				if (mprStrCmpAnyCase(header.contentMimeType, 
						"application/x-www-form-urlencoded") == 0 &&
						contentLength < 10000) {
					mprLog(3, tMod, "postData:\n%s\n", line);
				}

				inBuf->adjustStart(nbytes);
				remainingContent -= nbytes;
				if (remainingContent <= 0) {
					remainingContent = 0;
					enableReadEvents(0);
				}

				terminalHandler->postData(this, line, nbytes);
				inBuf->resetIfEmpty();
			}

			return;

		} else {
			end = inBuf->getEnd();
			for (cp = line; cp != end && *cp != '\n'; ) {
				cp++;
			}
			if (*cp == '\0') {
				if (inBuf->getSpace() <= 0) {
					requestError(400, "Header line too long");
				}
				return;
			}
			*cp = '\0';
			if (cp[-1] == '\r') {
				nbytes = cp - line;
				*--cp = '\0';
			} else {
				nbytes = cp - line;
			}
			inBuf->adjustStart(nbytes + 1);
			if (inBuf->getLength() >= (limits->maxHeader - 1)) {
				requestError(400, "Bad MPR_HTTP request");
				return;
			}
		}
		inBuf->resetIfEmpty();

		switch(state) {
		case MPR_HTTP_START:
			if (nbytes == 0) {
				mprAssert(0);
				break;
			}
			timeout = host->getTimeout();
			if (parseFirstLine(line) < 0) {
				return;
			}
			state = MPR_HTTP_HEADER;
			break;
		
		case MPR_HTTP_HEADER:
			if (nbytes > 1) {				// Always trailing newlines
				if (parseHeader(line) < 0) {
					mprLog(3, tMod, 
						"%d: processMaRequest: can't parse header\n", getFd());
					return;
				}

			} else {
				if (setupHandlers() != 0) {
					break;
				}
				//	Blank line means end of headers 
				if (flags & MPR_HTTP_POST_REQUEST) {
					if (contentLength < 0) {
						requestError(400, "Missing content length");
						break;
					}
					//
					//	Keep accepting read events
					// 
					flags |= MPR_HTTP_CONTENT_DATA;

				} else {
					enableReadEvents(0);
				}
				state = MPR_HTTP_RUN_HANDLERS;
				runHandlers();
			}
			break;

		default:
			mprLog(3, tMod, "%d: processMaRequest: bad state\n", getFd());
			requestError(404, "Bad state");
			return;
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Parse the first line of a http request
//

int MaRequest::parseFirstLine(char *line)
{
	char		*tok;
	int			len;

	mprAssert(line && *line);

	header.buf = mprStrdup(line);
	header.firstLine = mprStrdup(line);

	mprLog(3, tMod, "%d: Request from %s:%d to %s:%d\n", getFd(), 
		remoteIpAddr, remotePort,
		listenSock->getIpAddr(), listenSock->getPort());

	mprLog(3, tMod, "%d: parseFirstLine: <<<<<<<<<<<<<< \n# %s\n", 
		getFd(), header.buf);

	header.method = mprStrTok(header.buf, " \t", &tok);
	if (header.method == 0 || *header.method == '\0') {
		requestError(400, "Bad MPR_HTTP request");
		return MPR_ERR_BAD_STATE;
	}

	if (strcmp(header.method, "GET") == 0) {
		flags |= MPR_HTTP_GET_REQUEST;
		methodFlags |= MPR_HANDLER_GET;
		
	} else if (strcmp(header.method, "POST") == 0) {
		flags |= MPR_HTTP_POST_REQUEST;
		methodFlags |= MPR_HANDLER_POST;

	} else if (strcmp(header.method, "HEAD") == 0) {
		flags |= MPR_HTTP_HEAD_REQUEST;
		methodFlags |= MPR_HANDLER_HEAD;

	} else if (strcmp(header.method, "OPTIONS") == 0) {
		flags |= MPR_HTTP_OPTIONS_REQUEST;
		methodFlags |= MPR_HANDLER_OPTIONS;

#if FUTURE
	} else if (strcmp(header.method, "PUT") == 0) {
		flags |= MPR_HTTP_PUT_REQUEST;
		methodFlags |= MPR_HANDLER_PUT;

	} else if (strcmp(header.method, "DELETE") == 0) {
		flags |= MPR_HTTP_DELETE_REQUEST;
		methodFlags |= MPR_HANDLER_DELETE;
#endif

	} else if (strcmp(header.method, "TRACE") == 0) {
		flags |= MPR_HTTP_TRACE_REQUEST;
		methodFlags |= MPR_HANDLER_TRACE;

	} else {
		header.method = "UNKNOWN_METHOD";
		requestError(400, "Bad HTTP request");
		return MPR_ERR_BAD_STATE;
	}

	header.uri = mprStrTok(0, " \t\n", &tok);
	if (header.uri == 0 || *header.uri == '\0') {
		requestError(400, "Bad MPR_HTTP request");
		return MPR_ERR_BAD_STATE;
	}
	if (strlen(header.uri) >= (MPR_HTTP_MAX_URL - 1)) {
		requestError(400, "Bad MPR_HTTP request");
		return MPR_ERR_BAD_STATE;
	}

	//
	//	We parse (tokenize) the request uri first. Then we decode and lastly
	//	we validate the URI path portion. This allows URLs to have '?' in 
	//	the URL. We descape and validate insitu.
	//
	if (url.parse(header.uri) < 0) {
		requestError(400, "Bad URL format");
		return MPR_ERR_BAD_STATE;
	}

	uri = mprStrdup(url.uri);
	len = strlen(uri);

#if WIN
	//
	//	URLs are case insensitive. Map to lower case internally.
	//
	mprStrLower(uri);
#endif

	if (maDescapeUri(uri, len, uri) < 0) {
		requestError(400, "Bad URL escape");
		return MPR_ERR_BAD_STATE;
	}
	if (maValidateUri(uri) == 0) {
		requestError(400, "URL does not validate");
		return MPR_ERR_BAD_STATE;
	}

	if (url.ext == 0 || 
			(requestMimeType = host->lookupMimeType(url.ext)) == 0) {
		requestMimeType = "text/plain";
	}
	responseMimeType = mprStrdup(requestMimeType);

	header.proto = mprStrTok(0, " \t\n", &tok);
	if (header.proto == 0 || 
			(strcmp(header.proto, "HTTP/1.0") != 0 && 
			 strcmp(header.proto, "HTTP/1.1") != 0)) {
		requestError(400, "Unsupported protocol");
		return MPR_ERR_BAD_STATE;
	}

	flags |= MPR_HTTP_CREATE_ENV;
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return non-zero if the request is already handled (error or redirect)
//

int MaRequest::matchHandlers()
{
	MaHandler	*hp;
	char		path[MPR_MAX_FNAME];

	//
	//	matchHandlers may set location, extraPath and scriptName as 
	//	a side-effect.
	//
again:
	terminalHandler = host->matchHandlers(this, uri);
	if (terminalHandler == 0) {
		return 1;
	}

	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		if (hp->getFlags() & MPR_HANDLER_NEED_ENV) {
			flags |= MPR_HTTP_CREATE_ENV;
			break;
		}
		hp = (MaHandler*) handlers.getNext(hp);
	}

	//
	//	Now map the URI to an actual file name. This may set dir, fileName and
	//	may finish the request by error or redirect. If the URI is changed,
	//	mapToStorage will delete the handlers and request that we re-match.
	//
	if (host->mapToStorage(this, uri, path, sizeof(path), 
			MPR_HTTP_REDIRECT | MPR_HTTP_ADD_INDEX) < 0) {
		requestError(404, "Can't map URL to storage");
		return 1;
	}
	if (state == MPR_HTTP_START || state == MPR_HTTP_DONE) {
		//
		//	Looks like we've done a redirect. State will be START if using 
		//	keep-alive, otherwise DONE if the socket has been closed.
		//
		return 1;
	}
	if (handlers.getFirst() == 0) {
		//
		//	If a Alias has called deleteHandlers, we need to rematch
		//
		goto again;
	}

	if (setFileName(path) < 0) {
		//
		//	setFileName will return an error to the user
		//
		return 1;
	}

	//
	//	Not standard, but lots of servers define this. CGI/PHP needs it.
	//
	setVar("SCRIPT_FILENAME", path);

	//
	//	We will always get a dir match as a Directory object is created for
	//	the document root
	//
	if (dir == 0) {
		dir = host->findBestDir(path);
		mprAssert(dir);
		if (dir == 0) {
			requestError(404, "Can't map URL to directory");
			return 1;
		}
	}

	//
	//	Must not set PATH_TRANSLATED to empty string. CGI/PHP will try to 
	//	open it.
	//
	if (extraPath && host->mapToStorage(this, extraPath, path, 
			sizeof(path), 0) == 0) {
		setVar("PATH_TRANSLATED", path);
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::parseHeader(char *line)
{
	MaHost	*hp;
	char	keyBuf[MPR_HTTP_MAX_HEADER / 4];
	char	*browser, *key, *value, *tok, *cp;

#if BLD_FEATURE_LOG
	mprLog(3, MPR_RAW, tMod, "# %s\n", line);
#endif

	browser = 0;

	if ((key = mprStrTok(line, ": \t\n", &tok)) == 0) {
		requestError(400, "Bad header format");
		return MPR_ERR_BAD_ARGS;
	}

	if ((value = mprStrTok(0, "\n", &tok)) == 0) {
		value = "";
	}
	while (isspace(*value)) {
		value++;
	}
	mprStrUpper(key);
	for (cp = key; *cp; cp++) {
		if (*cp == '-') {
			*cp = '_';
		}
	}

	if (strspn(key, "%<>/\\") > 0) {
		requestError(400, "Bad header key value");
		return MPR_ERR_BAD_ARGS;
	}

	//
	//	Rest of the environment is created by createEnvironment()
	//	Note that value must be preserved
	//
	if (flags & MPR_HTTP_CREATE_ENV) {
		mprSprintf(keyBuf, sizeof(keyBuf) - 1, "HTTP_%s", key);
		setVar(keyBuf, value); 
	}

	//
	//	NOTE: no duping. key fields point directly into the line which is 
	//	preserved in request->header
	//
	//
	//	FUTURE OPT -- switch on first char
	//
	if (strcmp(key, "USER_AGENT") == 0) {
		mprFree(header.userAgent);
		header.userAgent = mprStrdup(value);

	} else if (strcmp(key, "AUTHORIZATION") == 0) {
		mprFree(header.authType);
		header.authType = mprStrdup(mprStrTok(value, " \t", &tok));
		header.authDetails = mprStrdup(tok);

	} else if (strcmp(key, "CONTENT_LENGTH") == 0) {
		contentLength = atoi(value);
		if (contentLength < 0 || contentLength >= limits->maxBody) {
			requestError(400, "Bad content length");
			return MPR_ERR_BAD_ARGS;
		}
		if (contentLength > 0) {
			flags |= MPR_HTTP_LENGTH;
		} else {
			contentLength = 0;
		}
		remainingContent = contentLength;

	} else if (strcmp(key, "CONTENT_TYPE") == 0) {
		header.contentMimeType = mprStrdup(value);
	
#if BLD_FEATURE_COOKIE || BLD_FEATURE_SESSION
	} else if (strcmp(key, "COOKIE") == 0) {
		flags |= MPR_HTTP_COOKIE;
		mprFree(header.cookie);
		header.cookie = mprStrdup(value);
#if BLD_FEATURE_SESSION
		if (strstr(value, "_appWebSessionId_") != 0) {
			mprFree(sessionId);
			getCrackedCookie(0, &sessionId, 0);
			session = host->lookupSession(sessionId);
			if (session == 0) {
				mprFree(sessionId);
				sessionId = 0;
			}
		}
#endif
#endif

#if BLD_FEATURE_KEEP_ALIVE
	} else if (strcmp(key, "CONNECTION") == 0) {
		mprStrUpper(value);
		if (strcmp(value, "KEEP-ALIVE") == 0) {
			flags |= MPR_HTTP_KEEP_ALIVE;
		}
#endif
		if (host->getHttpVersion() == MPR_HTTP_1_0) {
			flags &= ~MPR_HTTP_KEEP_ALIVE;
		}
#if BLD_FEATURE_KEEP_ALIVE
		if (!host->getKeepAlive()) {
			flags &= ~MPR_HTTP_KEEP_ALIVE;
		}
#endif

	} else if (strcmp(key, "HOST") == 0) {
		mprFree(header.host);
		header.host = mprStrdup(value);
		if (address->isNamedVhost()) {
			hp = address->findHost(value);
			if (hp == 0) {
				requestError(404, "No host to serve request");
				return MPR_ERR_BAD_ARGS;
			}
			//
			//	Reassign this request to a new host
			//
			host->removeRequest(this);
			host = hp;
			host->insertRequest(this);
		}

#if BLD_FEATURE_IF_MODIFIED
	} else if (strcmp(key, "IF_MODIFIED_SINCE") == 0) {
		char	*cmd, *cp;

		if ((cp = strchr(value, ';')) != 0) {
			*cp = '\0';
		}

		cmd = mprStrdup(value);
		if ((lastModified = maDateParse(cmd)) != 0) {
			flags |= MPR_HTTP_IF_MODIFIED;
		}
		mprFree(cmd);
#endif
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Called locally and also by the socket handler
//
//	Return TRUE if there is more data to write, < 0 if there is a write error.
//	If "completeRequired" is specified, "finishRequest" will be called when
//	there is not more write data.
//

int MaRequest::writeEvent(bool completeRequired)
{
	MaDataStream	*dp, *nextDp;
	MprBuf			*buf;
	int				len, bytes, written;

	mprLog(7, tMod, "%d: writeEvent completeRequired %d\n", getFd(), 
		completeRequired);
	setTimeMark();

	written = 0;
	while (1) {
		len = 0;
		dp = (MaDataStream*) outputStreams.getFirst();
		while (dp) {
			buf = &dp->buf;
			if ((len = buf->getLength()) > 0) {
				break;
			}
			if (buf->refill() > 0) {
				if ((len = buf->getLength()) > 0) {
					break;
				}
				continue;
			}
			nextDp = (MaDataStream*) outputStreams.getNext(dp);
			outputStreams.remove(dp);
			dp = nextDp;
		}
		if (dp == 0) {
			mprLog(8, tMod, "%d: writeEvent: end of data streams\n", getFd());
			enableWriteEvents(0);
			if (completeRequired) {
				finishRequest();
			}
			return 0;
		}

		len = buf->getLinearData();
		mprLog(7, tMod, "%d: writeEvent: using stream %s len %d\n", 
			getFd(), dp->getName(), len);

		if (dp == hdrBuf) {
			mprLog(3, tMod, "%d: response: >>>>>>>>>>>>\n\n%s", getFd(), 
				buf->getStart());
		} else {
#if JUST_FOR_DEBUG
			if (strcmp(responseMimeType, "text/html") == 0) {
				mprLog(4, MPR_RAW, tMod, "RETURN TO BROWSER =>\n%s", 
				buf->getStart());
			}
#endif
		}

		mprAssert(len > 0);
		bytes = sock->write(buf->getStart(), len);

		if (bytes < 0) {
			flags |= MPR_HTTP_INCOMPLETE;
			responseCode = MPR_HTTP_COMMS_ERROR;
			if (completeRequired) {
				finishRequest();
			}
			return bytes;

		} else if (bytes == 0) {
			//	Socket can't accept more data
			break;
		}
		buf->adjustStart(bytes);
		written += bytes;
		bytesWritten += bytes;
	}
	//
	//	More data yet to write
	//
	return written;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return 0 if the flush is finished, < 0 on errors and > 0 flushing is 
//	continuing in the background.
//

int MaRequest::flushOutput(bool background, bool completeRequired)
{
	char	allowBuf[80];
	int		rc, handlerFlags;

	mprAssert(state != MPR_HTTP_DONE);
	if (state == MPR_HTTP_DONE) {
		return MPR_ERR_BAD_STATE;
	}

	//
	//	Incase the handler does not implement HEAD
	//
	if (flags & (MPR_HTTP_HEAD_REQUEST | MPR_HTTP_TRACE_REQUEST |
			MPR_HTTP_OPTIONS_REQUEST)) {
		docBuf->buf.flush();
		docBuf->setSize(0);
		dynBuf->buf.flush();
		dynBuf->setSize(0);

		if (flags & MPR_HTTP_TRACE_REQUEST) {
			insertDataStream(dynBuf);
			dynBuf->buf.put(header.firstLine);
			dynBuf->buf.put("\r\n");
			dynBuf->setSize(strlen(header.firstLine) + 2);

		} else if (flags & MPR_HTTP_OPTIONS_REQUEST) {
			if (terminalHandler == 0) {
				mprSprintf(allowBuf, sizeof(allowBuf), "Allow: OPTIONS,TRACE");
			} else {
				handlerFlags = terminalHandler->getFlags();
				mprSprintf(allowBuf, sizeof(allowBuf), 
					"Allow: OPTIONS,TRACE%s%s%s", 
					(handlerFlags & MPR_HANDLER_GET) ? ",GET" : "",
					(handlerFlags & MPR_HANDLER_POST) ? ",POST" : "",
					(handlerFlags & MPR_HANDLER_PUT) ? ",PUT" : "",
					(handlerFlags & MPR_HANDLER_DELETE) ? ",DELETE" : "");
			}
			setHeader(allowBuf);
		}
	}

	mprLog(5, tMod, "%d: flushOutput: background %d\n", getFd(), background);

	if (!(flags & MPR_HTTP_HEADER_WRITTEN)) {
		writeHeaders();
	}

	if (outputStreams.getFirst() != 0) {
		if (background) {
			rc = backgroundFlush();
		} else {
			rc = foregroundFlush();
		}
		if (completeRequired && rc <= 0) {
			mprAssert(state != MPR_HTTP_DONE);
			mprAssert(sock != 0);
			finishRequest();
		}
		return rc;

	} else {
		if (completeRequired) {
			mprAssert(state != MPR_HTTP_DONE);
			mprAssert(sock != 0);
			finishRequest();
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return 0 if the flush is finished, < 0 on errors and > 0 flushing is 
//	continuing in the background.

int MaRequest::backgroundFlush()
{
	mprLog(5, tMod, "%d: backgroundFlush\n", getFd());

	if (writeEvent(0) < 0) {
		mprLog(6, tMod, "%d: backgroundFlush -- writeEvent error\n", getFd());
		return MPR_ERR_CANT_WRITE;
	}
	//
	//	Initiate a background flush if not already done and more data to go
	//
	if (outputStreams.getFirst() != 0) {
		MaDataStream *dp = (MaDataStream*) outputStreams.getFirst();
		mprLog(5, tMod, 
			"%d: flushOutput: start background flush for %d bytes\n", 
			getFd(), dp->getSize());
		enableWriteEvents(1);
		return 1;
	} else {
		enableWriteEvents(0);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return 0 if the flush is finished, < 0 on errors.
//

int MaRequest::foregroundFlush()
{
	bool	oldMode;
	int		alreadySetMode;

	mprLog(6, tMod, "%d: foregroundFlush\n", getFd());

	//
	//	Foreground (blocking) flush
	//
	oldMode = sock->getBlockingMode();
	alreadySetMode = 0;

	while (1) {
		if (writeEvent(0) < 0) {
			return MPR_ERR_CANT_WRITE;
		}
		if (outputStreams.getFirst() == 0) {
			break;
		}
		if (!alreadySetMode) {
			sock->setBlockingMode(1);
			alreadySetMode++;
		}
	}

	sock->setBlockingMode(oldMode);
	enableWriteEvents(0);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	For handlers that need to read their own post data on demand. This routine
//	will attempt to read and buffer ahead of the callers demands up to the
//	remaining content length. This routine will block and so should only really
//	be used in a multi-threaded server.
//
//	Returns the number of bytes read or < 0 if an error occurs while reading.
//

int MaRequest::readPostData(char *buf, int bufsize)
{
	bool	oldMode;
	int		sofar, thisRead, nbytes;

	if (! (flags & MPR_HTTP_PULL_POST)) {
		mprAssert(flags & MPR_HTTP_PULL_POST);
		return MPR_ERR_BAD_STATE;
	}

	for (sofar = 0; remainingContent > 0 && sofar < bufsize; ) {

		if (inBuf->getLength() == 0) {
			inBuf->resetIfEmpty();
			thisRead = min(inBuf->getLinearSpace(), remainingContent);

			//
			//	Do a blocking read. Don't ever read more than the 
			//	remaining content length. FUTURE -- need a timed read to 
			//	enable this for single-threaded servers.
			//
			oldMode = sock->getBlockingMode();
			sock->setBlockingMode(1);
			nbytes = sock->read(inBuf->getEnd(), thisRead);
			sock->setBlockingMode(oldMode);

			if (nbytes < 0) {
				return nbytes;

			} else if (nbytes == 0) {
				mprAssert(sock->getEof());
				return 0;

			} else if (nbytes > 0) {
				inBuf->adjustEnd(nbytes);
				inBuf->addNull();
			}
		}

		nbytes = min(remainingContent, inBuf->getLength());
		nbytes = min(nbytes, (bufsize - sofar));

		memcpy(&buf[sofar], inBuf->getStart(), nbytes);
		inBuf->adjustStart(nbytes);
		remainingContent -= nbytes;
		sofar += nbytes;
	}

	//
	//	NULL terminate just to make debugging easier
	//
	if (remainingContent == 0 && sofar < bufsize) {
		buf[sofar] = 0;
		if (mprStrCmpAnyCase(header.contentMimeType, 
				"application/x-www-form-urlencoded") == 0) {
			mprLog(3, tMod, 
				"%d: readPostData: ask %d bytes, got %d, remaining %d\n%s\n", 
				getFd(), bufsize, sofar, remainingContent, buf);
		}
	}
	return sofar;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setPullPost()
{
	flags |= MPR_HTTP_PULL_POST;
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::writeBlk(MaDataStream *dp, char *buf, int len)
{
	int		 rc, toWrite;
	
	rc = 0;
	toWrite = len;
	while (toWrite > 0) {
		rc = dp->buf.put((uchar*) buf, toWrite);
		dp->buf.addNull();
		if (rc < 0) {
			return rc;
		}

		if (rc != toWrite) {
			//
			//	We can't automatically calculate the content length as we
			//	must flush now without knowing the length of all the content.
			//	FUTURE -- We really should be using chunked transfers
			//
			flags |= MPR_HTTP_NO_LENGTH;
			if (flushOutput(MPR_HTTP_FOREGROUND_FLUSH, 0) < 0) {
				return MPR_ERR_CANT_WRITE;
			}
			//
			//	flushOutput will remove a stream when it is empty. Must re-add
			//	it now.
			//
			if (dp->head == 0) {
				insertDataStream(dp);
			}
		}
		buf += rc;
		toWrite -= rc;
	}
	return len;
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::write(char *buf, int len)
{
	return writeBlk(writeBuf, buf, len);
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::write(char *s)
{
	return write(s, strlen(s));
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::writeFmt(char *fmt, ...)
{
	va_list		vargs;
	char		buf[MPR_HTTP_BUFSIZE];
	int			len;
	
	va_start(vargs, fmt);

	len = mprVsprintf(buf, MPR_HTTP_BUFSIZE, fmt, vargs);
	if (len >= MPR_HTTP_BUFSIZE) {
		mprLog(MPR_VERBOSE, tMod, "%d: put buffer overflow\n", getFd());
		va_end(vargs);
		return 0;
	}
	va_end(vargs);
	return write(buf, len);
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::enableWriteEvents(bool on)
{
	int		oldMask = socketEventMask;

	mprLog(8, tMod, "%d: enableWriteEvents: %d\n", getFd(), on);
	if (flags & MPR_HTTP_BLOCKING) {
		return;
	}
	socketEventMask &= ~MPR_WRITEABLE;
	socketEventMask |= (on) ? MPR_WRITEABLE: 0;
	if (sock && socketEventMask != oldMask) {
		sock->setCallback(socketEventWrapper, this, socketEventMask, 
			MPR_NORMAL_PRIORITY);
	}
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::enableReadEvents(bool on)
{
	int		oldMask = socketEventMask;

	mprLog(8, tMod, "enableReadEvents %d\n", on);

	if (flags & MPR_HTTP_BLOCKING) {
		return;
	}
	socketEventMask &= ~MPR_READABLE;
	socketEventMask |= (on) ? MPR_READABLE: 0;
	if (sock && socketEventMask != oldMask) {
		sock->setCallback(socketEventWrapper, this, socketEventMask, 
			MPR_NORMAL_PRIORITY);
	}
}

////////////////////////////////////////////////////////////////////////////////

static void timeoutWrapper(void *arg, MprTimer *tp)
{
	MaRequest	*rq;
	int			delay;

	rq = (MaRequest*) arg;

	delay = rq->timeoutCheck();
	if (delay > 0) {
		tp->reschedule(delay);
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	WARNING: not called from select
//

int MaRequest::timeoutCheck()
{
	int		elapsed;

	elapsed = getTimeSinceLastActivity();
	if (elapsed >= timeout) {
		mprLog(5, tMod, "%d: timeoutCheck: timed out\n", getFd());

		stats.timeouts++;
		lock();
		if (timer) {
			timer->dispose();
			timer = 0;
		}
		flags |= MPR_HTTP_INCOMPLETE;
		responseCode = 408;
		finishRequest(MPR_HTTP_CLOSE);
		//
		//	This will unlock and delete the request.
		//
		unlock();
		return 0;

	} else {
		mprLog(6, tMod, "%d: timeoutCheck: elapsed %d, timeout %d diff %d\n", 
			getFd(), elapsed, timeout, timeout - elapsed);
	}
	return timeout;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::requestError(int code, char *fmt, ...)
{
	va_list		args;
	char		*logMsg, *buf, *fileName;

	mprAssert(fmt);

	stats.errors++;
	fileName = getFileName();
	if (fileName == 0) {
		fileName = "";
	}

	//
	//	Error codes above 700 are used by the unit test suite
	//
	if (code < 700 && code != 301 && code != 302) {
		logMsg = 0;
		va_start(args, fmt);
		mprAllocVsprintf(&logMsg, MPR_HTTP_BUFSIZE, fmt, args);
		va_end(args);
		mprError(MPR_L, MPR_LOG, "%d \"%s\" for \"%s\", file \"%s\": %s", 
			code, getErrorMsg(code), uri, fileName, logMsg);
		mprFree(logMsg);
	}

	buf = 0;
	mprAllocSprintf(&buf, MPR_HTTP_BUFSIZE, 
		"<HTML><HEAD><TITLE>Document Error: %s</TITLE></HEAD>\r\n"
		"<BODY><H2>Access Error: %d -- %s</H2>\r\n"
		"</BODY></HTML>\r\n",
		getErrorMsg(code), code, getErrorMsg(code));
	formatAltResponse(code, buf, MPR_HTTP_DONT_ESCAPE);
	mprFree(buf);

	flags |= MPR_HTTP_INCOMPLETE;
	cancelOutput();
	flushOutput(MPR_HTTP_FOREGROUND_FLUSH, MPR_HTTP_FINISH_REQUEST);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Redirect the user to another web page
// 

void MaRequest::redirect(int code, char *targetUrl)
{
	char	urlBuf[MPR_HTTP_MAX_URL], headerBuf[MPR_HTTP_MAX_URL];
	char	*uriDir, *cp, *hostName, *proto;

	mprAssert(targetUrl);
	stats.redirects++;

	mprLog(3, tMod, "%d: redirect %d %s\n", getFd(), code, targetUrl);

	if (code < 300 || code > 399) {
		code = 302;
	}

	if (strncmp(targetUrl, url.proto, strlen(url.proto)) != 0) {

		if (strchr(targetUrl, ':') == 0) {

			//
			//	Use the host name that came in the request by preference
			//	otherwise resort to the defined ServerName directive
			//
			if (header.host && *header.host) {
				hostName = header.host;
			} else {
				hostName = host->getName();
				//	Last resort -- rq->getIpAddr();
			}
#if BLD_FEATURE_SSL_MODULE
			if (host->isSecure()) {
				proto = "https";
			} else {
				proto = url.proto;
			}
#else
			proto = url.proto;
#endif

			if (*targetUrl == '/') {
				mprSprintf(urlBuf, sizeof(urlBuf), "%s://%s/%s", proto, 
					hostName, &targetUrl[1]);

			} else {
				uriDir = mprStrdup(uri);
				if ((cp = strrchr(uriDir, '/')) != 0) {
					*cp = '\0';
				}
				mprSprintf(urlBuf, sizeof(urlBuf), "%s://%s%s/%s", proto, 
					hostName, uriDir, targetUrl);
				mprFree(uriDir);
			}
			targetUrl = urlBuf;
		}
	}

	mprSprintf(headerBuf, sizeof(headerBuf), "Location: %s", targetUrl);
	setHeader(headerBuf, 0);
	setResponseCode(code);
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::formatAltResponse(int code, char *msg, int callFlags)
{
	MaDataStream	*saveBuf;
	char			buf[MPR_HTTP_MAX_ERR_BODY];
	char			*date;

	responseCode = code;
	saveBuf = writeBuf;
	writeBuf = hdrBuf;

#if BLD_FEATURE_KEEP_ALIVE
	if (responseCode != 200 && (responseCode < 301 || responseCode > 303)) {
		flags &= ~MPR_HTTP_KEEP_ALIVE;
	}
	if (flags & MPR_HTTP_INCOMPLETE) {
		flags &= ~MPR_HTTP_KEEP_ALIVE;
	}
#endif

	writeFmt("%s %d %s\r\n", header.proto, responseCode, 
		getErrorMsg(responseCode));
	outputHeader("Server: %s", MPR_HTTP_SERVER_NAME);
 
	if ((date = maGetDateString(0)) != 0) {
		outputHeader("Date: %s", date);
		mprFree(date);
	}
#if BLD_FEATURE_KEEP_ALIVE
	if (flags & MPR_HTTP_KEEP_ALIVE) {
		outputHeader("Connection: keep-alive");
		outputHeader("Keep-Alive: timeout=%d, max=%d", 
			host->getTimeout(), remainingKeepAlive);
	} else 
#endif
	{
		outputHeader("Connection: close");
	}
	outputHeader("Content-Type: text/html");
	flags |= MPR_HTTP_HEADER_WRITTEN;

	//
	//	Output any remaining custom headers
	//
	if (flags & MPR_HTTP_CUSTOM_HEADERS) {
		MprStringData	*sd, *nextSd;
		sd = (MprStringData*) responseHeaders->getFirst();
		while (sd) {
			nextSd = (MprStringData*) responseHeaders->getNext(sd);
			write(sd->getValue());
			write("\r\n");
			responseHeaders->remove(sd);
			delete sd;
			sd = nextSd;
		}
	}

	if ((flags & MPR_HTTP_HEAD_REQUEST) == 0 && msg && *msg) {
		outputHeader("Content-length: %d", strlen(msg) + 2);
		write("\r\n");
		if (callFlags & MPR_HTTP_DONT_ESCAPE) {
			writeFmt("%s\r\n", msg);
		} else {
			maEscapeHtml(buf, sizeof(buf), msg);
			writeFmt("%s\r\n", buf);
		}
	}
	writeBuf = saveBuf;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setHeaderFlags(int headerFlags)
{
	headerFlags &= 
		(MPR_HTTP_DONT_CACHE | MPR_HTTP_HEADER_WRITTEN | MPR_HTTP_NO_LENGTH);
	flags |= headerFlags;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setHeader(char *value, bool allowMultiple)
{
	char			*cp;
	MprStringData	*sd, *nextSd;
	int				len;
	
	if (! allowMultiple) {
		if ((cp = strchr(value, ':')) != 0) {
			len = cp - value;
		} else {
			len = strlen(value);
		}
		sd = (MprStringData*) responseHeaders->getFirst();
		while (sd) {
			nextSd = (MprStringData*) responseHeaders->getNext(sd);
			if (mprStrCmpAnyCaseCount(sd->getValue(), value, len) == 0) {
				responseHeaders->remove(sd);
				break;
			}
			sd = nextSd;
		}
	}
	responseHeaders->insert(value);
	flags |= MPR_HTTP_CUSTOM_HEADERS;
}

////////////////////////////////////////////////////////////////////////////////
//
//	For internal use only to output standard headers
//

void MaRequest::outputHeader(char *fmt, ...)
{
	MprStringData		*sd, *nextSd;
	va_list				vargs;
	char				*cp, buf[MPR_HTTP_BUFSIZE];
	int					len;
	
	va_start(vargs, fmt);
	mprVsprintf(buf, MPR_HTTP_MAX_HEADER, fmt, vargs);

	if (flags & MPR_HTTP_CUSTOM_HEADERS) {
		if ((cp = strchr(buf, ':')) != 0) {
			len = cp - buf;
		} else {
			len = strlen(buf);
		}
		sd = (MprStringData*) responseHeaders->getFirst();
		while (sd) {
			nextSd = (MprStringData*) responseHeaders->getNext(sd);
			if (mprStrCmpAnyCaseCount(sd->getValue(), buf, len) == 0) {
				write(sd->getValue());
				write("\r\n");
				responseHeaders->remove(sd);
				delete sd;
				return;
			}
			sd = nextSd;
		}
	}
	write(buf);
	write("\r\n");
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::writeHeaders()
{
	MprStringData	*sd, *nextSd;
	MaDataStream	*dp, *saveBuf;
	char			*date;
	int				bytes;

	saveBuf = writeBuf;
	writeBuf = hdrBuf;

	writeFmt("%s %d %s\r\n", header.proto, responseCode, 
		getErrorMsg(responseCode));

	date = maGetDateString(0);
	outputHeader("Date: %s", date);
	mprFree(date);

	outputHeader("Server: %s", MPR_HTTP_SERVER_NAME);

	if (flags & MPR_HTTP_DONT_CACHE) {
		//
		//	OLD HTTP/1.0 
		//		Pragma: no-cache
		//
		outputHeader("Cache-Control: no-cache");
	}

	outputHeader("Content-type: %s", 
		(responseMimeType) ? responseMimeType : "text/html");

	if (docBuf->head) {
		date = maGetDateString(&fileInfo);
		outputHeader("Last-modified: %s", date);
		mprFree(date);
	}
	if (etag) {
		outputHeader("ETag: %s", etag);
	}

	//
	//	Calculate the content length
	//
	if (flags & MPR_HTTP_NO_LENGTH) {
		//
		//	Can't do keep-alive as we don't know the length of the content
		//
		flags &= ~MPR_HTTP_KEEP_ALIVE;

	} else {
		if (docBuf->head || dynBuf->head) {
			bytes = 0;
			dp = (MaDataStream*) outputStreams.getFirst();
			while (dp) {
				if (dp != hdrBuf) {
					bytes += dp->getSize();
				}
				dp = (MaDataStream*) outputStreams.getNext(dp);
			}
			if (bytes > 0) {
				outputHeader("Content-length: %d", bytes);
			} else {
				flags &= ~MPR_HTTP_KEEP_ALIVE;
				// outputHeader("Content-length: 0");
			}

		} else {
			flags &= ~MPR_HTTP_KEEP_ALIVE;
			// outputHeader("Content-length: 0");
		}
	}

#if BLD_FEATURE_KEEP_ALIVE
	//
	//	Unread post data will pollute the channel. We could read it, but 
	//	since something has gone wrong -- better to close the connection.
	//
	if (flags & MPR_HTTP_CONTENT_DATA && remainingContent > 0) {
		flags &= ~MPR_HTTP_KEEP_ALIVE;
	}
	if (flags & MPR_HTTP_KEEP_ALIVE) {
		outputHeader("Connection: keep-alive");
		outputHeader("Keep-Alive: timeout=%d, max=%d", 
			host->getTimeout(), remainingKeepAlive);
	} else 
#endif
	{
		outputHeader("Connection: close");
	}

	//
	//	Output any remaining custom headers
	//
	if (flags & MPR_HTTP_CUSTOM_HEADERS) {
		sd = (MprStringData*) responseHeaders->getFirst();
		while (sd) {
			nextSd = (MprStringData*) responseHeaders->getNext(sd);
			write(sd->getValue());
			write("\r\n");
			responseHeaders->remove(sd);
			delete sd;
			sd = nextSd;
		}
	}
	
	//
	//	This marks the end of the headers
	//
	write("\r\n");
	flags |= MPR_HTTP_HEADER_WRITTEN;

	mprLog(6, tMod, "%d: writeHeaders. Headers =>\n%s", getFd(), 
		hdrBuf->buf.getStart());
	writeBuf = saveBuf;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Caller must delete the request object
//

void MaRequest::cancelRequest()
{
	lock();
	responseCode = 503;
	flags |= MPR_HTTP_INCOMPLETE;
	if (sock != 0) {
		mprLog(3, tMod, "%d: cancelRequest\n", getFd());
		//
		//	Take advantage that close() is idempotent
		//
		sock->close(MPR_SHUTDOWN_WRITE);
	}
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::finishRequest(int code, bool alsoCloseSocket)
{
	responseCode = code;
	finishRequest(alsoCloseSocket);
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::finishRequest(bool alsoCloseSocket)
{
	mprLog(5, tMod, "%d: finishRequest: alsoCloseSocket %d\n", getFd(), 
		alsoCloseSocket);

	//
	//	Need to synchronize with timeoutCheck() and CGI handler
	//
	lock();
	mprAssert(MPR_HTTP_START <= state && state <= MPR_HTTP_DONE);

	if (MPR_HTTP_START < state && state < MPR_HTTP_DONE) {
		state = MPR_HTTP_DONE;
		cancelTimeout();
		deleteHandlers();

#if BLD_FEATURE_KEEP_ALIVE && UNUSED
		if (responseCode != 200 && responseCode != 301 && responseCode != 302
				&& responseCode != 304) {
			flags &= ~MPR_HTTP_KEEP_ALIVE;
		}
#endif

		if (flags & MPR_HTTP_REUSE) {
			stats.keptAlive++;
		}

		if (flags & MPR_HTTP_OPENED_DOC) {
			file->close();
			flags &= ~MPR_HTTP_OPENED_DOC;
		}

#if BLD_FEATURE_ACCESS_LOG
		if (! (flags & MPR_HTTP_INCOMPLETE)) {
			logRequest();
		}
#endif
	}

#if BLD_FEATURE_KEEP_ALIVE
	if (!alsoCloseSocket && (flags & MPR_HTTP_KEEP_ALIVE) && 
			remainingKeepAlive > 0) {
		if (state != MPR_HTTP_START) {
			mprLog(5, tMod, 
				"%d: finishMaRequest: code %d, Attempting keep-alive\n", 
				getFd(), responseCode);
			reset();
			remainingKeepAlive--;
			flags |= MPR_HTTP_REUSE;
			if (!mprGetDebugMode()) {
				mprAssert(timer == 0);
				timeout = host->getKeepAliveTimeout();
				timer = new MprTimer(MPR_HTTP_TIMER_PERIOD, timeoutWrapper,
					(void*) this);
			}
			enableReadEvents(1);
		}

	} else 
#endif
	{
		closeSocket();
	}
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::closeSocket()
{
	if (sock != 0) {
		mprLog(5, tMod, "%d: closeSocket: code %d, Closing socket\n", getFd(), 
			responseCode);
		sock->close(MPR_SHUTDOWN_WRITE);
		sock->dispose();
		sock = 0;
	}
	if (head) {
		host->removeRequest(this);
	}
	flags |= MPR_HTTP_CONN_CLOSED;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_ACCESS_LOG

void MaRequest::logRequest()
{
	MaHost		*logHost;
	MprBuf		buf;
	time_t		tm;
	char		localBuffer[MPR_HTTP_MAX_URL + 256], timeBuf[64];
	char		*fmt, *cp, *value, *qualifier;
	char		c;

	logHost = host->getLogHost();
	if (logHost == 0) {
		return;
	}
	fmt = logHost->getLogFormat();
	if (fmt == 0) {
		return;
	}

	buf.setBuf((uchar*) localBuffer, (int) sizeof(localBuffer) - 1);

	while ((c = *fmt++) != '\0') {
		if (c != '%' || (c = *fmt++) == '%') {
			buf.put(c);
			continue;
		}

		switch (c) {
		case 'a':							// Remote IP
			buf.put(remoteIpAddr);
			break;

		case 'A':							// Local IP
			buf.put(listenSock->getIpAddr());
			break;

		case 'b':
			if (bytesWritten == 0) {
				buf.put('-');
			} else {
				buf.putInt(bytesWritten);
			} 
			break;

		case 'B':							// Bytes written (minus headers)
			buf.putInt(bytesWritten - hdrBuf->size);
			break;

		case 'h':							// Remote host
			buf.put(remoteIpAddr);
			break;

		case 'n':							// Local host
			if (header.host) {
				buf.put(header.host);
			} else {
				buf.put(url.host);
			}
			break;

		case 'l':							// Supplied in authorization
			if (user == 0) {
				buf.put('-');
			} else {
				buf.put(user);
			}
			break;

		case 'O':							// Bytes written (including headers)
			buf.put(bytesWritten);
			break;

		case 'r':							// First line of request
			buf.put(header.firstLine);
			break;

		case 's':							// Response code
			buf.putInt(responseCode);
			break;

		case 't':							// Time
			time(&tm);
			mprCtime(&tm, timeBuf, sizeof(timeBuf));
			if ((cp = strchr(timeBuf, '\n')) != 0) {
				*cp = '\0';
			}
			buf.put('[');
			buf.put(timeBuf);
			buf.put(']');
			break;

		case 'u':							// Remote username
			if (user == 0) {
				buf.put('-');
			} else {
				buf.put(user);
			}
			break;

		case '{':							// Header line
			qualifier = fmt;
			if ((cp = strchr(qualifier, '}')) != 0) {
				fmt = &cp[1];
				c = *fmt++;
				switch (c) {
				case 'i':
					if ((value = getVar(qualifier, 0)) != 0) {
						buf.put(value);
					}
					break;
				default:
					buf.put(qualifier);
				}
				*cp = '{';

			} else {
				buf.put(c);
			}
			break;

		case '>':
			if (*fmt == 's') {
				fmt++;
				buf.putInt(responseCode);
			}
			break;

		default:
			buf.put(c);
			break;
		}
	}
	buf.put('\n');
	buf.addNull();

	logHost->writeLog(buf.getStart(), buf.getLength());
}

#endif // BLD_FEATURE_HTTP_ACCESS_LOG 
////////////////////////////////////////////////////////////////////////////////

void MaRequest::reRunHandlers()
{
	int		len;

	//
	//	Re-examine the new URI
	//
	if (url.parse(uri) < 0) {
		requestError(400, "Bad URL format");
		return;
	}
	mprFree(uri);
	uri = mprStrdup(url.uri);
	len = strlen(uri);
	if (maDescapeUri(uri, len, uri) < 0) {
		requestError(400, "Bad URL escape");
		return;
	}
	if (maValidateUri(uri) == 0) {
		requestError(400, "URL does not validate");
		return;
	}
	if (url.ext == 0 || 
			(requestMimeType = host->lookupMimeType(url.ext)) == 0) {
		requestMimeType = "text/plain";
	}

	mprFree(responseMimeType);
	responseMimeType = mprStrdup(requestMimeType);

	mprLog(5, tMod, "%d: reRunHandlers: for %s\n", getFd(), uri);

	dir = 0;
	location = 0;

	deleteHandlers();
	if (setupHandlers() != 0) {
		return;
	}
	runHandlers();
}

////////////////////////////////////////////////////////////////////////////////
//
//	WARNING: the request can actually be processed here if it requires 
//	redirection. This can happen during matchHandlers()
//

int MaRequest::setupHandlers()
{
	MaHandler			*hp;

	//
	//	We can now trace the headers if required. Note -- not output in order!
	//
#if BLD_FEATURE_LOG && UNUSED
	if (tMod->getLevel() >= 4) {
		MprStringHashEntry	*ep;
		mprLog(3, tMod, "%d: %s: Request: \n\n< %s\n", getFd(), host->getName(),
			header.firstLine);
		ep = (MprStringHashEntry*) env->getFirst();
		while (ep) {
			char	*key;
			key = ep->getKey();
			if (strncmp(key, "HTTP_", 5) == 0) {
				key += 5;
			}
			mprLog(3, tMod, "# %s: %s\n", key, ep->getValue());
			ep = (MprStringHashEntry*) env->getNext(ep);
		}
		mprLog(3, tMod, "\n");
	}
#endif

	//
	//	Finish the header trace
	//
#if BLD_FEATURE_LOG
	mprLog(3, MPR_RAW, tMod, "#\n");
	mprLog(3, tMod, "%d: %s: is the serving host\n", getFd(), host->getName());
#endif

	if (file == 0) {
		file = fileSystem->newFile();
	}

	if (matchHandlers() != 0) {
		return 1;
	}

	if (flags & MPR_HTTP_CREATE_ENV) {
		createEnvironment();
	}

	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		mprLog(5, tMod, "%d: setupHandlers: %s\n", getFd(), hp->getName());
		hp->setup(this);
		hp = (MaHandler*) handlers.getNext(hp);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::runHandlers()
{
	MaHandler	*hp, *terminal;
	int			rc;

	state = MPR_HTTP_RUNNING;
	terminal = terminalHandler;

	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		if ((hp->getFlags() & methodFlags) || 
				(hp->getFlags() & MPR_HANDLER_ALWAYS)) {
			mprLog(3, tMod, "%d: runHandlers running: %s\n", 
				getFd(), hp->getName());
			currentHandler = hp;

			rc = hp->run(this);

			//
			//	NOTE: the request may have been finished and the request 
			//	structure may be reset here.
			//

			if (state == MPR_HTTP_RUN_HANDLERS) {
				reRunHandlers();
				return;
			}
			if (hp == terminal) {
				return;
			}
			if (state == MPR_HTTP_DONE || state == MPR_HTTP_START) {
				return;
			}
#if UNUSED
			//	MOB -- remove
			if (rc == MPR_HTTP_HANDLER_FINISHED_PROCESSING) {
				return;
			}
#endif
		} else {
			if (hp == terminalHandler) {
				if (methodFlags & (MPR_HANDLER_HEAD | 
						MPR_HANDLER_OPTIONS | MPR_HANDLER_TRACE)) {
					responseCode = MPR_HTTP_OK;
					flushOutput(MPR_HTTP_BACKGROUND_FLUSH, 
						MPR_HTTP_FINISH_REQUEST);
					return;
				}
				requestError(MPR_HTTP_BAD_METHOD, 
					"HTTP method \"%s\" is not supported by handler %s", 
					getMethod(), hp->getName());
				return;
			}
		}
		hp = (MaHandler*) handlers.getNext(hp);
	}
	requestError(MPR_HTTP_INTERNAL_SERVER_ERROR, "Request not processed");
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::deleteHandlers()
{
	MaHandler	*hp, *nextHp;

	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		mprLog(5, tMod, "%d: deleteHandlers: %s\n", getFd(), hp->getName());
		nextHp = (MaHandler*) handlers.getNext(hp);
		handlers.remove(hp);
		delete hp;
		hp = nextHp;
	}
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::createEnvironment()
{
	//
	//	WARNING: setVar requires a value that is preserved. setVar will not
	//	copy the data. So don't supply automatic data.
	//
	setVar("AUTH_TYPE", header.authType);
	mprItoa(contentLength, contentLengthStr, sizeof(contentLengthStr));
	setVar("CONTENT_LENGTH", contentLengthStr);
	setVar("CONTENT_TYPE", header.contentMimeType);
	setVar("DOCUMENT_ROOT", host->getDocumentRoot());
	setVar("GATEWAY_INTERFACE", "CGI/1.1");
	setVar("QUERY_STRING", url.query);
	setVar("REMOTE_ADDR", remoteIpAddr);

	if (user && *user) {
		setVar("REMOTE_USER", user);
	}

	//
	//	FUTURE -- should provide option for reverse DNS lookups on remoteIpAddr
	//
	setVar("REMOTE_HOST", remoteIpAddr);
	setVar("REQUEST_METHOD", header.method);
	setVar("REQUEST_URI", header.uri);
	mprItoa(listenSock->getPort(), localPort, sizeof(localPort) - 1);

	setVar("SERVER_ADDR", listenSock->getIpAddr());
	setVar("SERVER_PORT", localPort);
	setVar("SERVER_PROTOCOL", header.proto);
	setVar("SERVER_SOFTWARE", MPR_HTTP_SERVER_NAME);

	//	FUTURE: What is the difference between SERVER_NAME, HOST & URL
	setVar("SERVER_HOST", host->getName());
	setVar("SERVER_NAME", host->getName());
	setVar("SERVER_URL", host->getName());

	//
	//	Ensure some "HTTP_..." variables are defined
	//
	if (env->lookup("HTTP_HOST") == 0) {
		setVar("HTTP_HOST", "");
	}
	if (env->lookup("HTTP_USER_AGENT") == 0) {
		setVar("HTTP_USER_AGENT", "");
	}
	if (env->lookup("HTTP_ACCEPT") == 0) {
		setVar("HTTP_ACCEPT", "");
	}
	if (env->lookup("HTTP_CONNECTION") == 0) {
		setVar("HTTP_CONNECTION", "");
	}
	if (env->lookup("REMOTE_USER") == 0) {
		setVar("REMOTE_USER", "");
	}

	//
	//	Define variables for each keyword of the query. We don't do post data.
	//
	createEnvVars(url.query, strlen(url.query));
}

////////////////////////////////////////////////////////////////////////////////
//
//	Make environment variables for each keyword in a query. The buffer must
//	be urlencoded (ie. key=value&key2=value2..., spaces converted to '+' and
//	all else should be %HEX encoded).
//

void MaRequest::createEnvVars(char *buf, int len)
{
	char	*newValue, *decoded, *keyword, *value, *oldValue, *tok;

	decoded = (char*) mprMalloc(len + 1);
	decoded[len] = '\0';
	memcpy(decoded, buf, len);

	keyword = mprStrTok(decoded, "&", &tok);
	while (keyword != 0) {
		if ((value = strchr(keyword, '=')) != 0) {
			*value++ = '\0';
			maDescapeUri(keyword, strlen(keyword), keyword, 1);
			maDescapeUri(value, strlen(value), value, 1);

		} else {
			value = "";
		}

		if (*keyword) {
			//
			//	Append to existing keywords.
			//
			oldValue = getVar(keyword, 0);
			if (oldValue != 0) {
				mprAllocSprintf(&newValue, MPR_HTTP_MAX_HEADER, "%s %s", 
					oldValue, value);
				setVar(keyword, newValue);
				mprFree(newValue);
			} else {
				setVar(keyword, value);
			}
		}
		keyword = mprStrTok(0, "&", &tok);
	}
	mprFree(decoded);
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::testVar(char *var)
{
	return (env->lookup(var) != 0);
}

////////////////////////////////////////////////////////////////////////////////

char *MaRequest::getVar(char *var, char *defaultValue)
{
	MprStringHashEntry	*hp;
	char				*value;

	mprAssert(var && *var);
 
	hp = (MprStringHashEntry*) env->lookup(var);
	if (hp == 0) {
		value = defaultValue;
	} else {
		value = hp->getValue();
	}
	return value;
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::compareVar(char *var, char *value)
{
	mprAssert(var && *var);
	mprAssert(value && *value);
 
	if (strcmp(value, getVar(var, " __UNDEF__ ")) == 0) {
		return 1;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
 
void MaRequest::cancelTimeout()
{
	if (timer) {
		timer->stop(MPR_TIMEOUT_STOP);
		timer->dispose();
		timer = 0;
	}
}

////////////////////////////////////////////////////////////////////////////////
 
int MaRequest::getFlags()
{
	return flags;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setFlags(int orFlags, int andFlags)
{
	flags |= orFlags;
	flags &= andFlags;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_KEEP_ALIVE

void MaRequest::setNoKeepAlive()
{
	flags &= ~MPR_HTTP_KEEP_ALIVE;
}

#endif
////////////////////////////////////////////////////////////////////////////////

char *MaRequest::getOriginalUri()
{
	return header.uri;
}

////////////////////////////////////////////////////////////////////////////////

char *MaRequest::getUri()
{
	return uri;
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::getBytesWritten()
{
	return bytesWritten;
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::setFileName(char *newPath)
{
	char	tagBuf[64];

	mprFree(fileName);
	fileName = mprStrdup(newPath);

	// 
	//  Must not let the user set a non-regular file.
	//
	if (fileSystem->stat(newPath, &fileInfo) < 0 || !fileInfo.isReg) {

		mprAssert(terminalHandler);
		//
		//	Map virtual means the handler does not map the URL onto physical 
		//	storage. E.g. The EGI handler.
		//
		if (! (terminalHandler->getFlags() & MPR_HANDLER_MAP_VIRTUAL)) {
			requestError(404, "Can't access URL");
			return MPR_ERR_CANT_ACCESS;
		}
		if (etag) {
			mprFree(etag);
			etag = 0;
		}
		return 0;
	}

	mprSprintf(tagBuf, sizeof(tagBuf), "\"%x-%x-%x\"", fileInfo.inode, 
		fileInfo.size, fileInfo.mtime);
	mprFree(etag);
	etag = mprStrdup(tagBuf);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setUri(char *newUri)
{
	if (uri) {
		mprFree(uri);
	}
	uri = mprStrdup(newUri);
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::setExtraPath(char *prefix, int prefixLen)
{
	char	*cp;

	mprFree(scriptName);
	mprFree(extraPath);

	scriptName = mprStrdup(uri);

	//
	//	Careful, extraPath must either zero or be duped below
	//
	if (prefix) {
		extraPath = strchr(&scriptName[prefixLen + 1], '/');
	} else {
		extraPath = 0;
	}
	if (extraPath) {
		if (maValidateUri(extraPath) == 0) {
			return MPR_ERR_BAD_ARGS;
		}
		cp = extraPath;
		extraPath = mprStrdup(extraPath);
		*cp = 0;
		setVar("PATH_INFO", extraPath);

		mprFree(uri);
		uri = mprStrdup(scriptName);

	} else {
		setVar("PATH_INFO", "");
	}
	setVar("SCRIPT_NAME", scriptName);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setBytesWritten(int n)
{
	bytesWritten = n;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setResponseMimeType(char *mimeType)
{
	mprFree(responseMimeType);
	responseMimeType = mprStrdup(mimeType);
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setTimeMark()
{
	timestamp = mprGetTime(0);
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::getTimeSinceLastActivity()
{
	return mprGetTime(0) - timestamp;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::insertHandler(MaHandler *hp)
{
	handlers.insert(hp);
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::openDoc(char *path)
{
	int		fd;

	fd = file->open(path, O_RDONLY | O_BINARY, 0666);
	if (fd >= 0) {
		flags |= MPR_HTTP_OPENED_DOC;
	}
	return fd;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::closeDoc()
{
	flags &= ~MPR_HTTP_OPENED_DOC;
	file->close();
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::statDoc(MprFileInfo *fi)
{
	return fileSystem->stat(fileName, fi);
}

////////////////////////////////////////////////////////////////////////////////

bool MaRequest::isDir(char *path)
{
	return fileSystem->isDir(path);
}

////////////////////////////////////////////////////////////////////////////////

int MaRequest::readDoc(char *buf, int nBytes)
{
	return file->read(buf, nBytes);
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::seekDoc(long offset, int origin)
{
	file->lseek(offset, origin);
}

////////////////////////////////////////////////////////////////////////////////

static int refillDoc(MprBuf *bp, void *arg)
{
	MaRequest	*rq;
	int			len, rc;

	rq = (MaRequest*) arg;
	bp->flush();
	len = bp->getLinearSpace();
	rc = rq->readDoc(bp->getEnd(), bp->getLinearSpace());
	if (rc < 0) {
		return rc;
	}
	bp->adjustEnd(rc);
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

MaAuth *MaRequest::getAuth()
{
	if (location) {
		return location->getAuth();
	} else if (dir) {
		return dir->getAuth();
	} else {
		mprAssert(0);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

char *MaRequest::getAuthDetails()
{
	return header.authDetails;
}

////////////////////////////////////////////////////////////////////////////////

char *MaRequest::getAuthType()
{
	return header.authType;
}

////////////////////////////////////////////////////////////////////////////////

char *MaRequest::getQueryString()
{
	MprStringHashEntry		*hp;
	
	hp = (MprStringHashEntry*) env->lookup("QUERY_STRING");
	if (hp == 0) {
		return 0;
	}
	return hp->getValue();
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::insertDataStream(MaDataStream *dp)
{
	outputStreams.insert(dp);
}

////////////////////////////////////////////////////////////////////////////////

char *MaRequest::getErrorMsg(int code)
{
	return maGetHttpErrorMsg(code);
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::cancelOutput()
{
	MaDataStream	*dp;
	MaDataStream	*nextDp;

	dp = (MaDataStream*) outputStreams.getFirst();
	while (dp) {
		nextDp = (MaDataStream*) outputStreams.getNext(dp);
		if (dp != hdrBuf) {
			outputStreams.remove(dp);
		}
		dp = nextDp;
	}
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setScriptEngine(MprScriptEngine *engine)
{
	scriptEngine = engine;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_COOKIE || BLD_FEATURE_SESSION

char *MaRequest::getCookie()
{
	return header.cookie;
}

////////////////////////////////////////////////////////////////////////////////
//
//	This routine parses the cookie and returns the cookie name, value and path.
//	It can handle quoted and back-quoted args. All args may be null. Caller 
//	must free supplied args. 
//

int MaRequest::getCrackedCookie(char **name, char **value, char **path)
{
	char	*details, *keyValue, *tok, *key, *dp, *sp;
	int		seenSemi, seenValue;

	if (path) {
		*path = 0;
	}
	if (name) {
		*name = 0;
	}
	if (value) {
		*value = 0;
	}
	seenValue = 0;

	details = mprStrdup(header.cookie);
	key = details;

	while (*key) {
		while (*key && isspace(*key)) {
			key++;
		}
		tok = key;
		while (*tok && !isspace(*tok) && *tok != ';' && *tok != '=') {
			tok++;
		}
		if (*tok) {
			*tok++ = '\0';
		}

		while (isspace(*tok)) {
			tok++;
		}

		seenSemi = 0;
		if (*tok == '\"') {
			keyValue = ++tok;
			while (*tok != '\"' && *tok != '\0') {
				tok++;
			}
			if (*tok) {
				*tok++ = '\0';
			}

		} else {
			keyValue = tok;
			while (*tok != ';' && *tok != '\0') {
				tok++;
			}
			if (*tok) {
				seenSemi++;
				*tok++ = '\0';
			}
		}

		//
		//	Handle back-quoting
		//
		if (strchr(keyValue, '\\')) {
			for (dp = sp = keyValue; *sp; sp++) {
				if (*sp == '\\') {
					sp++;
				}
				*dp++ = *sp++;
			}
			*dp = '\0';
		}

		if (! seenValue) {
			if (name) {
				*name = mprStrdup(key);
			}
			if (value) {
				*value = mprStrdup(keyValue);
			}
			seenValue++;

		} else {
			switch (tolower(*key)) {
			case 'p':
				if (path && mprStrCmpAnyCase(key, "path") == 0) {
					*path = mprStrdup(keyValue);
				}
				break;

			default:
				//	Just ignore keywords we don't understand
				;
			}
		}

		key = tok;
		if (!seenSemi) {
			while (*key && *key != ';') {
				key++;
			}
			if (*key) {
				key++;
			}
		}
	}
	mprFree(details);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setCookie(char *name, char *value, int lifetime, char *path, 
	bool secure)
{
	struct tm 	tm;
	time_t		when;
	char 		dateStr[64];
	char		*cookieBuf;

	if (path == 0) {
		path = "/";
	}

	if (lifetime > 0) {
		when = time(0) + lifetime;
		mprGmtime(&when, &tm);
		mprRfcTime(dateStr, sizeof(dateStr), &tm);

		//
		//	Other keywords:
		//		Domain=%s
		//
		mprAllocSprintf(&cookieBuf, MPR_HTTP_MAX_HEADER, 
			"Set-Cookie: %s=%s; path=%s; Expires=%s; %s",
			name, value, path, dateStr, secure ? "secure" : "");

	} else {
		mprAllocSprintf(&cookieBuf, MPR_HTTP_MAX_HEADER, 
			"Set-Cookie: %s=%s; path=%s; %s",
			name, value, path, secure ? "secure" : "");
	}

	//
	//	Do not allow multiple cookies
	//
	setHeader(cookieBuf, 0);
	setHeader("Cache-control: no-cache=\"set-cookie\"", 0);
	mprFree(cookieBuf);
}

#endif // BLD_FEATURE_HTTP_COOKIE || BLD_FEATURE_SESSION
////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_SESSION
//
//	(Re)Create a new session. This will allocate a new session ID and set a 
//	cookie in the response header.
//

void MaRequest::createSession(int timeout)
{
	if (session) {
		destroySession();
	}

	session = host->createSession(timeout);
	mprAssert(session);

	mprLog(4, "New Session: %s\n", session->getId());
	sessionId = mprStrdup(session->getId());
	setCookie("_appWebSessionId_", sessionId, host->getSessionTimeout(), "/", 
#if BLD_FEATURE_SSL_MODULE
		host->isSecure()
#else
		0
#endif
		);
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::destroySession()
{
	if (session) {
		mprLog(4, "Destroy Session: %s\n", session->getId());
		host->destroySession(session);
		session = 0;
		mprFree(sessionId);
		sessionId = 0;
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Set an item of session data.  Create a new session if non exists
//

void MaRequest::setSessionData(char *key, char *value)
{
	if (session == 0) {
		createSession(0);
	}
	session->set(key, value);
	mprLog(4, "setSessionData: %s = %s\n", key, value);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Lookup an item of session data. Create a new session if non exists.
//

char *MaRequest::getSessionData(char *key, char *defaultValue)
{
	char	*value;

	if (session == 0) {
		createSession(0);
	}
	value = session->get(key);
	if (value == 0 && defaultValue) {
		return defaultValue;
	}
	return value;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Unset an item of session data. Create a new session if non exists.
//

int MaRequest::unsetSessionData(char *key)
{
	if (session == 0) {
		createSession(0);
		return MPR_ERR_NOT_FOUND;
	}
	mprLog(4, "unsetSessionData: %s\n", key);
	return session->unset(key);
}

#endif // BLD_FEATURE_SESSION
////////////////////////////////////////////////////////////////////////////////
//	MOB -- this should be conditional on something

void MaRequest::setPassword(char *password)
{
	mprFree(this->password);
	this->password = mprStrdup(password);
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setUser(char *user)
{
	mprFree(this->user);
	this->user = mprStrdup(user);
}

////////////////////////////////////////////////////////////////////////////////

void MaRequest::setGroup(char *group)
{
	mprFree(this->group);
	this->group = mprStrdup(group);
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaDataStream /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaDataStream::MaDataStream(char *name, int initial, int max)
{
	this->name = mprStrdup(name);
	buf.setBuf(initial, max);
	size = 0;
}

////////////////////////////////////////////////////////////////////////////////

MaDataStream::~MaDataStream()
{
	mprFree(name);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaHeader ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaHeader::MaHeader()
{
	authType = 0;
	authDetails = 0;
	buf = 0;
	firstLine = 0;
	method = 0;
	proto = 0;
	uri = 0;
	contentMimeType = 0;
	userAgent = 0;
	authType = 0;
	host = 0;
#if BLD_FEATURE_COOKIE || BLD_FEATURE_SESSION
	cookie = 0;
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaHeader::~MaHeader()
{
	reset();
}

////////////////////////////////////////////////////////////////////////////////

void MaHeader::reset()
{
	if (authDetails) {
		mprFree(authDetails);
		authDetails = 0;
	}
	if (authType) {
		mprFree(authType);
		authType = 0;
	}
	if (firstLine) {
		mprFree(firstLine);
		firstLine = 0;
	}
	if (contentMimeType) {
		mprFree(contentMimeType);
		contentMimeType = 0;
	}
	if (userAgent) {
		mprFree(userAgent);
		userAgent = 0;
	}
#if BLD_FEATURE_COOKIE || BLD_FEATURE_SESSION
	if (cookie) {
		mprFree(cookie);
		cookie = 0;
	}
#endif
	if (host) {
		mprFree(host);
		host = 0;
	}

	if (buf) {
		mprFree(buf);
		buf = 0;
	}
	method = 0;
	proto = 0;
	uri = 0;
}

////////////////////////////////////////////////////////////////////////////////

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
