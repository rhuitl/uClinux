///
///	@file 	host.cpp
/// @brief 	Host class for all HTTP hosts
///
///	The Host class is used for the default HTTP server and for all virtual
///	hosts (including SSL hosts). Many objects are controlled at the host 
///	level. Eg. URL handlers.
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

//////////////////////////////////// Code //////////////////////////////////////

MaHost::MaHost(MaServer *sp)
{
	memset((void*) &stats, 0, sizeof(stats));

#if BLD_FEATURE_LOG
	tMod = new MprLogModule("httpHost");
#endif

	authEnabled = 1;
	documentRoot = 0;
	flags = 0;
	httpVersion = MPR_HTTP_1_1;
	ipAddr = 0;
	limits = sp->http->getLimits();
	name = 0;
	timeout = MPR_HTTP_SERVER_TIMEOUT;

#if BLD_FEATURE_SESSION
	sessions = new MprHashTable(29);
	sessionTimeout = MPR_HTTP_SESSION_TIMEOUT;
#endif

#if BLD_FEATURE_KEEP_ALIVE
	keepAliveTimeout = MPR_HTTP_KEEP_TIMEOUT;
	maxKeepAlive = MPR_HTTP_MAX_KEEP_ALIVE;
	keepAlive = 1;
#endif

#if BLD_FEATURE_ACCESS_LOG
	logHost = 0;
	logPath = 0;
	logFormat = 0;
	logFd = -1;
#endif

	secret = 0;
	server = sp;
	mimeTypes = 0;

	aliasService = new MaAliasService();

#if BLD_FEATURE_SSL_MODULE
	secure = 0;
#endif
#if BLD_FEATURE_DLL
	moduleDirs = 0;
#endif

#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaHost::~MaHost()
{
	MaRequest		*rq, *nextRq;
	MaDir			*dp, *nextDp;
	MaLocation		*lp, *nextLp;

	//
	//	Problems here because we close sockets while requests have them open.
	//	Deadly-embraces between socket close/handler delete and select/socket.
	//
	rq = (MaRequest*) requests.getFirst();
	while (rq) {
		nextRq = (MaRequest*) requests.getNext(rq);
		rq->cancelRequest();
		rq = nextRq;
	}

	dp = (MaDir*) dirs.getFirst();
	while (dp) {
		nextDp = (MaDir*) dirs.getNext(dp);
		dirs.remove(dp);
		delete dp;
		dp = nextDp;
	}

	lp = (MaLocation*) locations.getFirst();
	while (lp) {
		nextLp = (MaLocation*) locations.getNext(lp);
		locations.remove(lp);
		delete lp;
		lp = nextLp;
	}

	if (mimeTypes && !(flags & MPR_HTTP_HOST_REUSE_MIME)) {
		delete mimeTypes;
	}

#if BLD_FEATURE_ACCESS_LOG
	if (logPath) {
		mprFree(logPath);
	}
	if (logFormat) {
		mprFree(logFormat);
	}
#endif
#if BLD_FEATURE_SESSIONS
	delete sessions;
#endif

	mprFree(documentRoot);
	mprFree(name);
	mprFree(ipAddr);
	mprFree(secret);
	delete aliasService;

#if BLD_FEATURE_DLL
	mprFree(moduleDirs);
#endif
#if BLD_FEATURE_LOG
	delete tMod;
#endif
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
}

////////////////////////////////////////////////////////////////////////////////

int MaHost::start()
{
	char	*hex = "0123456789abcdef";
	uchar	bytes[MPR_HTTP_MAX_SECRET];
	char	ascii[MPR_HTTP_MAX_SECRET * 2 + 1], *ap;
	int		i;

	//
	//	Create a random secret for use in authentication. Block and make sure
	//	we get the best entropy possible.
	//
	mprLog(7, "Get random bytes\n");
	if (mprGetRandomBytes(bytes, sizeof(bytes), 1) < 0) {
		mprError(MPR_L, MPR_LOG, "Can't generate local secret");
		return MPR_ERR_CANT_INITIALIZE;
	}
	ap = ascii;
	for (i = 0; i < (int) sizeof(bytes); i++) {
		*ap++ = hex[bytes[i] >> 4];
		*ap++ = hex[bytes[i] & 0xf];
	}
	*ap = '\0';
	secret = mprStrdup(ascii);
	mprLog(7, "Got %d random bytes\n", sizeof(bytes));

#if BLD_FEATURE_ACCESS_LOG && !BLD_FEATURE_ROMFS
	if (logPath) {
		logFd = open(logPath, O_CREAT | O_APPEND | O_WRONLY | O_TEXT, 0664);
		if (logFd < 0) {
			mprError(MPR_L, MPR_LOG, "Can't open log file %s", logPath);
		}
#if FUTURE
		rotateLog();
#endif
	}
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaHost::stop()
{
	MaHandler	*hp, *nextHp;

	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		nextHp = (MaHandler*) handlers.getNext(hp);
		handlers.remove(hp);
		delete hp;
		hp = nextHp;
	}


#if BLD_FEATURE_ACCESS_LOG
	if (logFd >= 0) {
		close(logFd);
		logFd = -1;
	}
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_ACCESS_LOG

void MaHost::setLog(char *path, char *format)
{
	char	*src, *dest;

	mprAssert(path && *path);
	mprAssert(format && *format);

	logPath = mprStrdup(path);
	logFormat = mprStrdup(format);

	for (src = dest = logFormat; *src; src++) {
		if (*src == '\\' && src[1] != '\\') {
			continue;
		}
		*dest++ = *src;
	}
	*dest = '\0';
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::setLogHost(MaHost *host)
{
	logHost = host;
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::writeLog(char *buf, int len)
{
	static int once = 0;
	if (write(logFd, buf, len) != len && once++) {
		mprError(MPR_L, MPR_LOG, "Can't write to access log %s", logPath);
	}
}

////////////////////////////////////////////////////////////////////////////////
#if FUTURE
//
//	Called to rotate the access log
//
void MaHost::rotateLog()
{
	struct stat	sbuf;
	char		fileBuf[MPR_MAX_FNAME];
	struct tm	tm;
	time_t		when;

	//
	//	Rotate logs when full
	//
	if (fstat(logFd, &sbuf) == 0 && sbuf.st_mode & S_IFREG && 
			(unsigned) sbuf.st_size > maxSize) {

		char bak[MPR_MAX_FNAME];

		time(&when);
		mprGmtime(&when, &tm);

		mprSprintf(bak, sizeof(bak), "%s-%02d-%02d-%02d-%02d:%02d:%02d", 
			logPath, 
			tm->tm_mon, tm->tm_mday, tm->tm_year, tm->tm_hour, tm->tm_min, 
			tm->tm_sec);

		close(logFd);
		rename(logPath, bak);
		unlink(logPath);

		logFd = open(logPath, O_CREAT | O_TRUNC | O_WRONLY | O_TEXT, 0664);
		logConfig();
	}
}

#endif // FUTURE
#endif
////////////////////////////////////////////////////////////////////////////////

void MaHost::setDocumentRoot(char *dir) 
{
	MaAlias		*ap;

	documentRoot = mprStrdup(dir);

	//
	//	This is the catch-all alias
	//
	ap = new MaAlias("", dir);
	insertAlias(ap);
}

////////////////////////////////////////////////////////////////////////////////

int MaHost::openMimeTypes(char *path)
{
	MprFile		*file;
	char		buf[80], *tok, *ext, *type;
	int			line;

	mprAssert(mimeTypes == 0);
	file = server->fileSystem->newFile();
	
	if (mimeTypes == 0) {
		mimeTypes = new MprHashTable(157);
	}
	if (file->open(path, O_RDONLY | O_TEXT, 0444) < 0) {
		mprError(MPR_L, MPR_LOG, "Can't open mime file %s", path);
		delete file;
		return MPR_ERR_CANT_OPEN;
	}
	line = 0;
	while (file->gets(buf, sizeof(buf)) != 0) {
		line++;
		if (buf[0] == '#' || isspace(buf[0])) {
			continue;
		}
		type = mprStrTok(buf, " \t\n\r", &tok);
		ext = mprStrTok(0, " \t\n\r", &tok);
		if (type == 0 || ext == 0) {
			mprError(MPR_L, MPR_LOG, "Bad mime spec in %s at line %d", 
				path, line);
			continue;
		}
		while (ext) {
			addMimeType(ext, type);
			ext = mprStrTok(0, " \t\n\r", &tok);
		}
	}
	file->close();
	delete file;
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Add a mime type to the mime lookup table. Action Programs are added 
//	separately.
//

void MaHost::addMimeType(char *ext, char *mimeType)
{
	if (*ext == '.') {
		ext++;
	}
	if (mimeTypes == 0) {
		mprError(MPR_L, MPR_LOG, 
			"Mime types file is not yet defined.\nIgnoring mime type %s", 
			mimeType);
		return;
	}
	mimeTypes->insert(new MaMimeHashEntry(ext, mimeType));
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::setMimeActionProgram(char *mimeType, char *actionProgram)
{
	MaMimeHashEntry		*mt;

	mt = (MaMimeHashEntry*) mimeTypes->getFirst();
	while (mt) {
		if (strcmp(mt->getMimeType(), mimeType) == 0) {
			mt->setActionProgram(actionProgram);
			return;
		}
		mt = (MaMimeHashEntry*) mimeTypes->getNext(mt);
	}
	mprError(MPR_L, MPR_LOG, "Can't find mime type %s", mimeType);
}

////////////////////////////////////////////////////////////////////////////////

char *MaHost::getMimeActionProgram(char *mimeType)
{
	MaMimeHashEntry		*mt;

	mt = (MaMimeHashEntry*) mimeTypes->getFirst();
	while (mt) {
		if (strcmp(mt->getMimeType(), mimeType) == 0) {
			return mt->getActionProgram();
		}
		mt = (MaMimeHashEntry*) mimeTypes->getNext(mt);
	}
	mprError(MPR_L, MPR_LOG, "Can't find mime type %s", mimeType);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::setMimeTypes(MprHashTable *table)
{
	lock();
	mimeTypes = table;
	flags |= MPR_HTTP_HOST_REUSE_MIME;
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

MprHashTable *MaHost::getMimeTypes()
{
	return mimeTypes;
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::insertRequest(MaRequest *rq)
{
	lock();
	requests.insert(rq);
	mprAssert(stats.activeRequests >= 0);
	stats.requests++;
	stats.activeRequests++;
	if (stats.activeRequests > stats.maxActiveRequests) {
		stats.maxActiveRequests = stats.activeRequests;
	}
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Remove request and aggregate stats
//

void MaHost::removeRequest(MaRequest *rq)
{
	lock();
	requests.remove(rq);
	mprAssert(stats.activeRequests > 0);
	stats.activeRequests--;
	//
	//	Aggregate the request stats
	//
	stats.errors += rq->stats.errors;
	stats.keptAlive += rq->stats.keptAlive;
	stats.redirects += rq->stats.redirects;
	stats.timeouts += rq->stats.timeouts;
	stats.copyDown += rq->stats.copyDown;
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

int MaHost::insertAlias(MaAlias *item)
{
	return aliasService->insertAlias(item);
}

////////////////////////////////////////////////////////////////////////////////

char *MaHost::lookupMimeType(char *ext)
{
	MprStringHashEntry	*hp;

	hp = (MprStringHashEntry*) mimeTypes->lookup(ext);
	if (hp == 0) {
		return 0;
	}
	return hp->getValue();
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::setName(char *str)
{
	lock();
	if (name) {
		mprFree(name);
	}
	name = mprStrdup(str);
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::setIpAddr(char *str)
{
	lock();
	if (ipAddr) {
		mprFree(ipAddr);
	}
	ipAddr = mprStrdup(str);
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

bool MaHost::isVhost()
{
	return (bool) ((flags & MPR_HTTP_VHOST) != 0);
}

////////////////////////////////////////////////////////////////////////////////

bool MaHost::isNamedVhost()
{
	return (bool) ((flags & MPR_HTTP_NAMED_VHOST) != 0);
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::setVhost()
{
	flags |= MPR_HTTP_VHOST;
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::setNamedVhost()
{
	flags |= MPR_HTTP_NAMED_VHOST;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_DLL

void MaHost::setModuleDirs(char *path)
{
	mprFree(moduleDirs);
	moduleDirs = mprStrdup(path);
}

#endif // BLD_FEATURE_DLL
////////////////////////////////////////////////////////////////////////////////

void MaHost::insertHandler(MaHandler *item)
{
	lock();
	handlers.insert(item);
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

MaHandler *MaHost::lookupHandler(char *name)
{
	MaHandler		*hp;

	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		if (strcmp(hp->getName(), name) == 0) {
			return hp;
		}
		hp = (MaHandler*) handlers.getNext(hp);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::copyHandlers(MaHost *host)
{
	MaHandler			*hp;
	MaHandlerService	*hs;

	//
	//	Copy inherited handlers (if not already installed)
	//
	hp = (MaHandler*) host->handlers.getFirst();
	while (hp) {
		if (lookupHandler(hp->getName()) == 0) {
			hs = server->http->lookupHandlerService(hp->getName());
			mprAssert(hs);
			insertHandler(hs->newHandler(host->getServer(), this, 
				hp->getExtensions()));
		}
		hp = (MaHandler*) host->handlers.getNext(hp);
	}
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::deleteHandlers()
{
	MaHandler		*hp, *nextHp;

	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		nextHp = (MaHandler*) handlers.getNext(hp);
		handlers.remove(hp);
		hp = nextHp;
	}
}

////////////////////////////////////////////////////////////////////////////////

int MaHost::insertLocation(MaLocation *item)
{
	MaLocation	*lp;
	int			rc;

	//
	//	Sort in reverse collating sequence. Must make sure that /abc/def sorts
	//	before /abc
	//
	lock();
	lp = (MaLocation*) locations.getFirst();
	while (lp) {
		rc = strcmp(item->getPrefix(), lp->getPrefix());
		if (rc == 0) {
			unlock();
			return MPR_ERR_ALREADY_EXISTS;
		}
		if (strcmp(item->getPrefix(), lp->getPrefix()) > 0) {
			lp->insertPrior(item);
			unlock();
			return 0;
		}
		lp = (MaLocation*) locations.getNext(lp);
	}
	locations.insert(item);
	unlock();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the terminal handler that will actually process the request
//

MaHandler *MaHost::matchHandlers(MaRequest *rq, char *uri)
{
	MaHandler	*hp, *cloneHp;
	MaLocation	*lp;
	int			uriLen, rc;

	mprAssert(rq);
	mprAssert(uri);

	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		if (hp->flags & MPR_HANDLER_ALWAYS) {
			cloneHp = hp->cloneHandler();
			rq->insertHandler(cloneHp);
			if (hp->getFlags() & MPR_HANDLER_TERMINAL) {
				return cloneHp;
			}
		}
		hp = (MaHandler*) handlers.getNext(hp);
	}

	//
	//	Match by URI prefix first. A URI may have an extra path segment after
	//	the URI (E.g. /cgi-bin/scriptName/some/Extra/Path. We need to know where
	//	the URI ends. NOTE: ScriptAlias directives are handled here.
	//
	lp = (MaLocation*) locations.getFirst();
	while (lp) {
		if (lp->getHandlerName() != 0) {
			rc = strncmp(lp->getPrefix(), uri, lp->getPrefixLen());
			if (rc == 0) {
				if (rq->setExtraPath(lp->getPrefix(), lp->getPrefixLen()) < 0) {
					rq->requestError(400, "Extra path does not validate");
					return 0;
				}
				rq->setLocation(lp);
				hp = lookupHandler(lp->getHandlerName());
				if (hp == 0) {
					mprAssert(hp != 0);
					continue;
				}
				cloneHp = hp->cloneHandler();
				rq->insertHandler(cloneHp);
				if (hp->getFlags() & MPR_HANDLER_TERMINAL) {
					return cloneHp;
				}
				break;
			}
		}
		lp = (MaLocation*) locations.getNext(lp);
	}
	rq->setExtraPath(0, -1);

	//
	//	Now match by extension or by any custom handler matching technique
	//
	uriLen = strlen(uri);
	hp = (MaHandler*) handlers.getFirst();
	while (hp) {
		if (hp->matchRequest(rq, uri, uriLen)) {
			if (! (hp->getFlags() & MPR_HANDLER_ALWAYS)) {
				cloneHp = hp->cloneHandler();
				rq->insertHandler(cloneHp);
				if (hp->getFlags() & MPR_HANDLER_TERMINAL) {
					return cloneHp;
				}
			}
		}
		hp = (MaHandler*) handlers.getNext(hp);
	}
	rq->requestError(404, "No handler for URL: %s", uri);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::insertDir(MaDir *item)
{
	MaDir		*dp;

	//
	//	Sort in reverse collating sequence. Must make sure that /abc/def sorts
	//	before /abc
	//
	lock();
	dp = (MaDir*) dirs.getFirst();
	while (dp) {
		if (strcmp(item->getPath(), dp->getPath()) >= 0) {
			dp->insertPrior(item);
			unlock();
			return;
		} 
		dp = (MaDir*) dirs.getNext(dp);
	}
	dirs.insert(item);
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Find an exact match. May be called with raw file names. ie. D:\myDir
//

MaDir *MaHost::findDir(char *path)
{
	MaDir		*dp;
	char		buf[MPR_MAX_FNAME];
	char		*dirPath;
	int			len;

	mprGetFullPathName(buf, sizeof(buf) - 1, path);
	len = strlen(buf);
	if (buf[len - 1] != '/') {
		buf[len] = '/';
		buf[++len] = '\0';
	}
#if WIN
	//
	//	Windows is case insensitive for file names. Always map to lower case.
	//
	mprStrLower(buf);
#endif

	dp = (MaDir*) dirs.getFirst();
	while (dp) {
		dirPath = dp->getPath();
		if (dirPath != 0 && strcmp(dirPath, buf) == 0) {
			return dp;
		}
		dp = (MaDir*) dirs.getNext(dp);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Find best match. The directory must match or be a parent of path.
//	Not called with raw files names. They will be lower case and only have
//	forward slashes.
//

MaDir *MaHost::findBestDir(char *path)
{
	MaDir	*dp;

	dp = (MaDir*) dirs.getFirst();
	while (dp) {
#if WIN
		if (mprStrCmpAnyCaseCount(dp->getPath(), path, dp->getPathLen()) == 0)
#else
		if (strncmp(dp->getPath(), path, dp->getPathLen()) == 0)
#endif
		{
			if (dp->getPathLen() > 0) {
				return dp;
			}
		}
		dp = (MaDir*) dirs.getNext(dp);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MprList *MaHost::getDirs()
{
	return &dirs;
}

////////////////////////////////////////////////////////////////////////////////

MprList *MaHost::getLocations()
{
	return &locations;
}

////////////////////////////////////////////////////////////////////////////////

MprList *MaHost::getHandlers()
{
	return &handlers;
}

////////////////////////////////////////////////////////////////////////////////

char *MaHost::makePath(char *buf, int buflen, char *file, bool validate)
{
	char	tmp[MPR_MAX_FNAME];

	mprAssert(file);

	if (replaceReferences(buf, buflen, file) == 0) {
		//  Overflow
		return 0;
	}

	if (*buf == '\0' || strcmp(buf, ".") == 0) {
		mprStrcpy(tmp, sizeof(tmp), server->getServerRoot());

#if WIN
	} else if (*buf != '/' && buf[1] != ':' && buf[2] != '/') {
		mprSprintf(tmp, buflen, "%s/%s", server->getServerRoot(), buf);
#else
	} else if (*buf != '/') {
		mprSprintf(tmp, buflen, "%s/%s", server->getServerRoot(), buf);
#endif

	} else {
		mprStrcpy(tmp, sizeof(tmp), buf);
	}

	mprGetFullPathName(buf, buflen, tmp);

	//
	//	Valided removes "." and ".." from the path and map '\\' to '/'
	//	Restore "." if the path is now empty.
	//
	if (validate) {
		maValidateUri(buf);
		if (*buf == '\0') {
			mprStrcpy(buf, buflen, ".");
		}
	}
	return buf;
}

////////////////////////////////////////////////////////////////////////////////
//
//  Return 0 on overflow. FUTURE -- should replace this with allocated buffers
//
char *MaHost::replaceReferences(char *buf, int buflen, char *str)
{
	char	*src, *dest, *key, *root;
	int		len;

	dest = buf;
	buflen--;
	for (src = str; *src && buflen > 0; ) {
		if (*src == '$') {
			*dest = '\0';
			key = "DOCUMENT_ROOT";
			if (strncmp(++src, key, strlen(key)) == 0 ) {
				root = getDocumentRoot();
				if (root) {
					mprStrcpy(dest, buflen, root);
				}
			} else {
				key = "SERVER_ROOT";
				if (strncmp(src, key, strlen(key)) == 0) {
					mprStrcpy(dest, buflen, server->getServerRoot());
				}
			}
			if (*dest) {
				len = strlen(dest);
				dest += len;
				buflen -= len;
				src += strlen(key);
				continue;
			}
		}
		*dest++ = *src++;
		buflen--;
	}

	if (buflen <= 0) {
		return 0;
	}

	*dest = '\0';

	return buf;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_SSL_MODULE
//	MOB -- locking

void MaHost::setSecure(bool on)
{
	secure = on;
}

#endif
////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_SESSION
//
//	Create a new session including the session ID.
//

MaSession *MaHost::createSession(int timeout)
{
	MaSession	*sp;
	char		idBuf[64], *id;
	static int	idCount = 0;

	mprSprintf(idBuf, sizeof(idBuf), "%x%d", this, idCount++);
	id = maMD5(idBuf);

	if (timeout <= 0) {
		timeout = sessionTimeout;
	}
	sp = new MaSession(this, id, timeout);
	mprFree(id);

	lock();
	sessions->insert(sp);
	unlock();
	return sp;
}

////////////////////////////////////////////////////////////////////////////////

void MaHost::destroySession(MaSession *session)
{
	lock();
	delete session;
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

MaSession *MaHost::lookupSession(char *sessionId)
{
	MaSession	*sp;

	mprAssert(sessionId && *sessionId);

	lock();
	sp = (MaSession*) sessions->lookup(sessionId);
	unlock();
	return sp;
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// MaSession /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static void sessionTimeoutProc(void *data, MprTimer *tp)
{
	MaSession 	*sp = (MaSession*) data;
	MaHost		*host;

	sp->lock();
	if (sp->getLastActivity() > sp->getTimeoutStart()) {
		sp->setTimeoutStart(mprGetTime(0));
		tp->reschedule();
		sp->unlock();
		return;
	}
	mprLog(4, "Delete session %s\n", sp->getId());
	host = sp->getHost();
	host->getSessions()->remove(sp);
	delete sp;
	//	No unlock as it is now deleted
}

////////////////////////////////////////////////////////////////////////////////

MaSession::MaSession(MaHost *host, char *sessionId, int timeout) : 
	MprHashEntry(sessionId)
{
	this->host = host;
	sessionData = new MprHashTable(47);
	timeoutStart = mprGetTime(0);
	lastActivity = timeoutStart;
	expiryTimer = new MprTimer(timeout * 1000, sessionTimeoutProc, this);
#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
#endif
	mprLog(4, "Create session %s\n", getId());
}

////////////////////////////////////////////////////////////////////////////////

MaSession::~MaSession()
{
	if (expiryTimer) {
		expiryTimer->dispose();
	}
	delete sessionData;
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
}

////////////////////////////////////////////////////////////////////////////////

void MaSession::set(char *key, char *value)
{
	lock();
	sessionData->insert(new MprStringHashEntry(key, value));
	lastActivity = mprGetTime(0);
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

int MaSession::unset(char *key)
{
	int		rc;

	lock();
	rc = sessionData->remove(key);
	lastActivity = mprGetTime(0);
	unlock();
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

char *MaSession::get(char *key)
{
	MprStringHashEntry	*se;

	lock();
	se = (MprStringHashEntry*) sessionData->lookup(key);
	lastActivity = mprGetTime(0);
	unlock();

	if (se == 0) {
		return 0;
	}
	//
	//	Note: as we return a pointer into the session cache. It is up to the
	//	caller to ensure they do not delete session values while other threads
	//	may be accessing them.
	//
	return se->getValue();
}

#endif // BLD_FEATURE_SESSION
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaMimeHashEntry /////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Construct a new string hash entry. Always duplicate the value.
//

MaMimeHashEntry::MaMimeHashEntry(char *ext, char *mimeType) : 
	MprHashEntry(ext)
{
	this->mimeType = mprStrdup(mimeType);
	actionProgram = 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Virtual destructor.
//

MaMimeHashEntry::~MaMimeHashEntry()
{
	mprFree(mimeType);
	mprFree(actionProgram);
}

////////////////////////////////////////////////////////////////////////////////

void MaMimeHashEntry::setActionProgram(char *actionProgram)
{
	mprFree(this->actionProgram);
	this->actionProgram = mprStrdup(actionProgram);
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
