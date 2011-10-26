///
///	@file 	cgiHandler.cpp
/// @brief 	Common Gateway Interface Handler
///
///	Support the CGI/1.1 standard for external gateway programs to respond to
///	HTTP requests.
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
/////////////////////////////////// Includes ///////////////////////////////////

#include	"cgiHandler.h"

//////////////////////////////// Forward Declarations //////////////////////////
#if BLD_FEATURE_CGI_MODULE

static void cgiOutputData(MprCmd *cmd, void *data);

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// CgiModule //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int mprCgiInit(void *handle)
{
	if (maGetHttp() == 0) {
		return MPR_ERR_NOT_INITIALIZED;
	}
	new MaCgiModule(handle);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MaCgiModule::MaCgiModule(void *handle) : MaModule("cgi", handle)
{
	cgiHandlerService = new MaCgiHandlerService();
}

////////////////////////////////////////////////////////////////////////////////

MaCgiModule::~MaCgiModule()
{
	delete cgiHandlerService;
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////// MaCgiHandlerService //////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaCgiHandlerService::MaCgiHandlerService() : MaHandlerService("cgiHandler")
{
#if BLD_FEATURE_LOG
	log = new MprLogModule("cgi");
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaCgiHandlerService::~MaCgiHandlerService()
{
#if BLD_FEATURE_LOG
	delete log;
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaHandler *MaCgiHandlerService::newHandler(MaServer *server, MaHost *host, 
	char *extensions)
{
	return new MaCgiHandler(extensions, log);
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaCgiHandler /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaCgiHandler::MaCgiHandler(char *extensions, MprLogModule *serviceLog) : 
	MaHandler("cgiHandler", extensions, 
		MPR_HANDLER_GET | MPR_HANDLER_POST | MPR_HANDLER_MAP_VIRTUAL |
		MPR_HANDLER_NEED_ENV | MPR_HANDLER_TERMINAL)
{
	log = serviceLog;
	cmd = new MprCmd();
	cgiFlags = 0;
	newLocation = 0;
	headerBuf = new MprBuf(MPR_HTTP_IN_BUFSIZE, MPR_HTTP_MAX_BODY);
}

////////////////////////////////////////////////////////////////////////////////
 
MaCgiHandler::~MaCgiHandler()
{
	cmd->dispose();
	if (newLocation) {
		mprFree(newLocation);
	}
	delete headerBuf;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Note: stdOut and stdIn names are from the perspective of the client.
//

int MaCgiHandler::setup(MaRequest *rq)
{
	mprLog(5, log, "%d: setup\n", rq->getFd());
	if (cmd->makeStdio("cgi", 
			MPR_CMD_STDIN | MPR_CMD_STDOUT | MPR_CMD_PIPES) < 0){
		mprError(MPR_L, MPR_LOG, "Can't open CGI output files");
		return MPR_ERR_CANT_OPEN;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	NOTE: we run the CGI script immediately before calling postData.
//	This routine will write the post data to the CGI program.
//

void MaCgiHandler::postData(MaRequest *rq, char *buf, int len)
{
	int		fd, rc;

	fd = cmd->getWriteFd();
	mprAssert(fd >= 0);

	if (len < 0 && rq->getRemainingContent() > 0) {
		//
		//	CGI programs must recognize short CONTENT_LENGTHS and abort 
		//	appropriately.
		//
		cmd->closeWriteFd();
		mprLog(5, log, "%d: postData short post data, len %d, remaining %d\n",
			rq->getFd(), len, rq->getRemainingContent());

	} else {
		rc = write(fd, buf, len);
		mprLog(5, log, "%d: postData to fd %d, %d bytes, rc %d, errno %d\n", 
			rq->getFd(), fd, len, rc, errno);
		if (rc != len) {
			rq->requestError(MPR_HTTP_BAD_GATEWAY, "Cant write to CGI program");
		}
	}
}

////////////////////////////////////////////////////////////////////////////////

MaHandler *MaCgiHandler::cloneHandler()
{
	return new MaCgiHandler(extensions, log);
}

////////////////////////////////////////////////////////////////////////////////

int MaCgiHandler::parseConfig(char *key, char *value, MaServer *server, 
	MaHost *host, MaAuth *auth, MaDir *dir, MaLocation *location)
{
	char	*program, *mimeType;

	if (mprStrCmpAnyCase(key, "Action") == 0) {
		if (server->splitValue(&mimeType, &program, value, 1) < 0) {
			return MPR_ERR_BAD_SYNTAX;
		}
		host->setMimeActionProgram(mimeType, program);
		return 1;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaCgiHandler::run(MaRequest *rq)
{
	MprStringHashEntry	*vp;
	MprHashTable		*env;
	char				*cp, *query, **argv, **envv, **ep, *fileName, *baseName;
	int					i, argc, envc;

	query = 0;
	argv = 0;
	env = 0;
	argc = 0;

	hitCount++;
	rq->setResponseCode(200);
	rq->setHeaderFlags(MPR_HTTP_DONT_CACHE);
	rq->insertDataStream(rq->getDynBuf());

	//
	//	Build the commmand line arguments
	//
	query = mprStrdup(rq->getQueryString());
	argc = 1;									// argv[0] == programName
	if (*query) {
		argc++;
		maDescapeUri(query, strlen(query), query);
		for (cp = query; *cp; cp++) {
			if (*cp == '+') {
				argc++;
			}
		}
	}

	//
	//	Note: buildArgs may modify query
	//
	buildArgs(&argc, &argv, cmd, rq, query);
	fileName = argv[0];

	rq->setResponseMimeType("text/html");

	baseName = mprGetBaseName(fileName);
	if (strncmp(baseName, "nph-", 4) == 0) {
		cgiFlags |= MPR_CGI_NON_PARSED_HEADER;
	}
	if (strlen(baseName) > 4 && 
			strcmp(&baseName[strlen(baseName) - 4], "-nph") == 0) {
		cgiFlags |= MPR_CGI_NON_PARSED_HEADER;
	}

	//
	//	Build environment variables
	//
	env = rq->getEnv();
	envc = env->getNumItems() + 1;
	envv = (char**) mprMalloc(envc * sizeof(char*));
	i = 0;
	vp = (MprStringHashEntry*) env->getFirst();
	while (vp) {
		mprAllocSprintf(&envv[i], MPR_MAX_FNAME, "%s=%s", vp->getKey(),
			vp->getValue());
		vp = (MprStringHashEntry*) env->getNext(vp);
		i++;
	}
	envv[i] = 0;
	mprAssert(envc == (i+1));

	mprLog(4, log, "%d: running program: %s\n", rq->getFd(), fileName);

	if (cmd->start(fileName, argv, envv, cgiOutputData, (void*) rq, 
			MPR_CMD_CHDIR) < 0) {
		rq->requestError(503, "Can't run CGI process: %s, URI %s",
			rq->getScriptName(), rq->getOriginalUri());
		goto exit;
	}

exit:
	for (i = 0; i < argc; i++) {
		mprFree(argv[i]);
	}
	for (ep = envv; *ep; ep++) {
		mprFree(*ep);
	}
	mprFree(query);
	mprFree(argv);
	mprFree(envv);

	return MPR_HTTP_HANDLER_FINISHED_PROCESSING;
}

////////////////////////////////////////////////////////////////////////////////
//
//	WARNING: when multi-threaded, this may be called at the same time that 
//	postData is called -- each on a different thread. This is because they
//	are using different file descriptors to select on and the MPR will only
//	serialize requests on a single descriptor. The request can't be deleted
//	from underneath us as if anyone else calls finishRequest, it will try
//	to delete this handler which will block.
//
static void cgiOutputData(MprCmd *cmd, void *arg)
{
	MaRequest		*rq;
	MaCgiHandler	*cp;

	rq = (MaRequest*) arg;
	cp = (MaCgiHandler*) rq->getCurrentHandler();

	//
	//	Note: the only person who ever deletes the Request is the
	//	socketEventWrapper in request.cpp. We must lock here to ensure
	//	that while this thread is running, we must not clash with another 
	//	thread which may be writing post data or otherwise modifying
	//	the request.
	//
	//	NOTE: lock will increment an inUse counter so that the request will
	//	not never be actually deleted until we do an unlock.
	//
	rq->lock();
	cp->outputData(rq);
	rq->unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Read the output data from the CGI script and return it to the client
//

void MaCgiHandler::outputData(MaRequest *rq)
{
	MaDataStream	*dynBuf;
	char			buf[MPR_HTTP_BUFSIZE + 1], *scriptName;
	int				nRead, fd, exitCode, contentLength, err, code;

	fd = cmd->getReadFd();
	mprAssert(fd >= 0);
	dynBuf = rq->getDynBuf();
	scriptName = rq->getScriptName();

	if (cgiFlags & MPR_CGI_NON_PARSED_HEADER) {
		//
		//	Pretend we have seen and parsed the CGI response header
		//
		cgiFlags |= MPR_CGI_HEADER_SEEN;
		rq->setHeaderFlags(MPR_HTTP_HEADER_WRITTEN);

#if BLD_FEATURE_KEEP_ALIVE
		//
		//	We don't know if the client will always include a content-length.
		//	So to be safe, we must close the socket after this request.
		//
		rq->setNoKeepAlive();
#endif
	}

	for (;;) {
		nRead = read(fd, buf, sizeof(buf) - 1);

		mprLog(5, log, "%d: CGI Response: read %d bytes\n", rq->getFd(), nRead);
		if (nRead > 0) {
			buf[nRead] = 0;
			mprLog(7, log, "%d: Data is: \n%s", rq->getFd(), buf);
		}

		if (nRead < 0) {
			err = mprGetOsError();
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN || err == EWOULDBLOCK) {
				return;
			}
			rq->requestError(502, "CGI Gateway error");
			return;

		} else if (nRead == 0) {
			break;
		}

		if (!(cgiFlags & MPR_CGI_HEADER_SEEN)) {
			if (headerBuf->put((uchar*) buf, nRead) != nRead) {
				rq->requestError(504, "CGI header too large");
				return;
			}
			headerBuf->addNull();
			parseHeader(rq);

		} else if (newLocation == 0) {
			if (rq->writeBlk(dynBuf, buf, nRead) < 0) {
				rq->finishRequest(MPR_HTTP_COMMS_ERROR, MPR_HTTP_CLOSE);
				return;
			}
		}
	}

	if (cmd->getExitCode(&exitCode) < 0 || exitCode != 0) {
		rq->requestError(503, 
			"CGI process %s: exited abnormally with exit code: %d", 
			scriptName, exitCode);
		return;
	}
	code = rq->getResponseCode();

#if UNUSED
	//
	//	We now allow any response code
	//
	if (code != 200) {
		rq->requestError(code, "CGI process %s failed with HTTP code %d", 
			scriptName, code);
		return;
	}
#endif

	mprLog(5, log, "%d: outputData: exitCode %d, requestCode %d\n", 
		rq->getFd(), exitCode, code);

	if (!(cgiFlags & MPR_CGI_HEADER_SEEN)) {
		rq->requestError(503, "Header not seen");
		return;
	}

	if (newLocation) {
		dynBuf->flush();
		if (*newLocation == '/') {
			rq->setUri(newLocation);
			//
			//	Will return the redirected content immediately to the client
			//
			rq->reRunHandlers();

		} else {
			//
			//	Will issue a redirect to the client who will refetch
			//
			rq->redirect(302, newLocation);
			rq->flushOutput(MPR_HTTP_FOREGROUND_FLUSH, MPR_HTTP_FINISH_REQUEST);
		}
		//
		//	WARNING: this handler is deleted from here on ...
		//
		return;
	}

	flags = rq->getFlags();
	contentLength = dynBuf->buf.getLength();
	if (contentLength > 0) {
		dynBuf->setSize(contentLength);
	}
	rq->flushOutput(MPR_HTTP_BACKGROUND_FLUSH, MPR_HTTP_FINISH_REQUEST);
}

////////////////////////////////////////////////////////////////////////////////

void MaCgiHandler::parseHeader(MaRequest *rq)
{
	MaDataStream	*dynBuf;
	char			*endHeaders, *header, *key, *value, *tok;
	char			*cp, *lp, *saveHeader;
	int				len;

	header = headerBuf->getStart();
	endHeaders = strstr(header, "\r\n\r\n");
	if (endHeaders == 0) {
		endHeaders = strstr(header, "\n\n");
		if (endHeaders == 0) {
			return;
		}
		headerBuf->adjustStart(endHeaders + 2 - header);
	} else {
		headerBuf->adjustStart(endHeaders + 4 - header);
	}
	*endHeaders = '\0';

	mprLog(5, log, "%d: parseHeader: header\n%s\n", rq->getFd(), header);

	if (endHeaders) {
		lp = header;
		tok = lp;
		while (tok && *tok) {

			for (cp = tok; *cp && *cp != '\r' && *cp != '\n'; cp++) 
				;
			len = cp - tok + 1;
			mprAllocMemcpy(&saveHeader, len, tok, len);
			saveHeader[len - 1] = '\0';

			if ((key = mprStrTok(lp, ": \t\r\n", &tok)) == 0) {
				break;
			}
			lp = 0;

			if ((value = mprStrTok(0, "\r\n", &tok)) == 0) {
				rq->requestError(503, "Bad header format");
				mprFree(saveHeader);
				return;
			}
			while (isspace(*value)) {
				value++;
			}
			mprStrLower(key);

			if (strcmp(key, "location") == 0) {
				mprFree(newLocation);
				newLocation = mprStrdup(value);

			} else if (strcmp(key, "status") == 0) {
				rq->setResponseCode(atoi(value));

			} else if (strcmp(key, "content-type") == 0) {
				rq->setResponseMimeType(value);

#if OLD
			} else if ((key[0] == 'x' || key[0] == 'X') && key[1] == '-') {
				//
				//	Pass "X-Headers" through to the client
				//
				rq->setHeader(saveHeader);
			}
#endif
			} else {
				//
				//	Now pass all other headers back to the client
				//
				rq->setHeader(saveHeader);
			}
			mprFree(saveHeader);
		}
		cgiFlags |= MPR_CGI_HEADER_SEEN;
		dynBuf = rq->getDynBuf();
		//
		//	Write content data to the client
		//
		while (headerBuf->getLength() > 0) {
			len = headerBuf->getLinearData();
			if (rq->writeBlk(dynBuf, headerBuf->getStart(), len) < 0) {
				rq->finishRequest(MPR_HTTP_COMMS_ERROR, MPR_HTTP_CLOSE);
				return;
			}
			headerBuf->adjustStart(len);
		}
	}
	return;
}

////////////////////////////////////////////////////////////////////////////////
//
//	NOTE: argv is untrusted input. BuildArgs will modify query.
//

void MaCgiHandler::buildArgs(int *argcp, char ***argvp, MprCmd *cmd, 
	MaRequest *rq, char *query)
{
	char	*fileName, **argv, *cp, *tok, *program, *cmdScript, *actionProgram;
	char	statusBuf[8];
	int		argc, argind;

	fileName = rq->getFileName();
	program = cmdScript = 0;
	argind = 0;
	argc = *argcp;

	actionProgram = rq->host->getMimeActionProgram(rq->getRequestMimeType());
	if (actionProgram != 0) {
		argc++;
		//
		//	This is an Apache compatible hack
		//
		mprItoa(MPR_HTTP_MOVED_TEMPORARILY, statusBuf, sizeof(statusBuf));
		rq->setVar("REDIRECT_STATUS", statusBuf);
	}

#if WIN
	char	escapeBuf[MPR_HTTP_MAX_URL], buf[MPR_HTTP_MAX_URL];
	char	*dp, *bangScript, *cmdBuf;
	int		size, len;

	//
	//	On windows we attempt to find an executable matching the fileName.
	//	We look for *.exe, *.bat and also do unix style processing "#!/program"
	//
	findExecutable(&program, &cmdScript, &bangScript, rq, fileName);
	mprAssert(program);

	if (cmdScript) {
		//
		//	Cmd/Batch script (.bat | .cmd)
		//	Convert the command to the form where there are 4 elements in argv
		//	that cmd.exe can interpret.
		//
		//		argv[0] = cmd.exe
		//		argv[1] = /Q
		//		argv[2] = /C
		//		argv[3] = ""script" args ..."
		//
		argc = 4;
		argv = (char**) mprMalloc((argc + 1) * sizeof(char*));
		argv[argind++] = program;				// Duped in findExecutable
		argv[argind++] = mprStrdup("/Q");
		argv[argind++] = mprStrdup("/C");

		//
		//	The resulting cmd string could worst case have every character
		//	quoted (with carets) and real quotes around each arg. So need 
		//	2x the size of the query plus 2 * argc. Plus 9 -- for four 
		//	quotes, "/C ", and a space after script and a null terminator.
		//
		size = strlen(cmdScript) + (strlen(query) * 2) + (argc * 2) + 9;
		cmdBuf = (char*) mprMalloc(size);
		len = mprSprintf(cmdBuf, size, "\"\"%s\"", cmdScript);

		dp = &cmdBuf[len];
		cp = mprStrTok(query, "+", &tok);
		while (cp) {
			*dp++ = ' ';
			//
			//	Each arg including the filename must be quoted and escaped 
			//	(Caret) for dangerous characters.
			//
			buf[0] = '\"';
			mprStrcpy(&buf[1], sizeof(buf) - 3, cp);
			strcpy(&buf[strlen(buf)], "\"");
			maEscapeCmd(escapeBuf, sizeof(escapeBuf), buf, '^');

			strcpy(dp, escapeBuf);
			dp += strlen(escapeBuf);

			cp = mprStrTok(0, "+", &tok);
		}
		*dp++ = '\"';
		*dp = '\0';
		argv[argind++] = cmdBuf;

		cmd->setCwd(cmdScript);
		mprFree(cmdScript);
		//	program will get freed when argv[] gets freed
		
	} else if (bangScript) {
		//
		//	Script used "#!/program". NOTE: this may be overridden by a mime
		//	Action directive.
		//
		argc++;
		argv = (char**) mprMalloc((argc + 1) * sizeof(char*));
		argv[argind++] = program;		// Will get freed when argv[] is freed
		argv[argind++] = bangScript;	// Will get freed when argv[] is freed
		cp = mprStrTok(query, "+", &tok);
		while (cp) {
			if (*cp == '\"') {
				mprStrcpy(buf, sizeof(buf), cp);
			} else {
				mprSprintf(buf, sizeof(buf), "\"%s\"", cp);
			}
			argv[argind++] = mprStrdup(buf);
			cp = mprStrTok(0, "+", &tok);
		}
		cmd->setCwd(bangScript);

	} else {
		//
		//	Either unknown extension or .exe program.
		//
		argv = (char**) mprMalloc((argc + 1) * sizeof(char*));
		if (actionProgram) {
			argv[argind++] = mprStrdup(actionProgram);
		}
		argv[argind++] = program;
		cp = mprStrTok(query, "+", &tok);
		while (cp) {
			if (*cp == '\"') {
				mprStrcpy(buf, sizeof(buf), cp);
			} else {
				mprSprintf(buf, sizeof(buf), "\"%s\"", cp);
			}
			argv[argind++] = mprStrdup(buf);
			cp = mprStrTok(0, "+", &tok);
		}
	}
#else
	argv = (char**) mprMalloc((argc + 1) * sizeof(char*));
	if (actionProgram) {
		argv[argind++] = mprStrdup(actionProgram);
	}
	argv[argind++] = mprStrdup(fileName);
	cp = mprStrTok(query, "+", &tok);
	while (cp) {
		argv[argind++] = mprStrdup(cp);
		cp = mprStrTok(0, "+", &tok);
	}
#endif
	mprAssert(argind == argc);

	argv[argind] = 0;
	*argcp = argc;
	*argvp = argv;
}

////////////////////////////////////////////////////////////////////////////////
#if WIN
//
//	If the program has a UNIX style "#!/program" string at the start of the file
//	that program will be selected and the original program will be passed as the
//	first arg to that program with argv[] appended after that. If the program
//	is not found, this routine supports a safe intelligent search for the 
//	command. If all else fails, we just return in program the fileName we were
//	passed in. script will be set if we are modifying the program to run and
//	we have extracted the name of the file to run as a script.
//

void MaCgiHandler::findExecutable(char **program, char **script, 
	char **bangScript, MaRequest *rq, char *fileName)
{
	MprStringData	*ep;
	char			buf[MPR_MAX_FNAME + 1], pathBuf[MPR_MAX_FNAME];
	char			dirBuf[MPR_MAX_FNAME + 1], tmp[MPR_MAX_FNAME];
	char			*cmdShell, *tok, *ext, *actionProgram;

	*bangScript = 0;
	*script = 0;
	*program = 0;
	actionProgram = rq->host->getMimeActionProgram(rq->getRequestMimeType());

	//
	//	If not found, go looking for the fileName with the extensions 
	//	defined in http.conf. NOTE: we don't use PATH deliberately!!!
	//
	ext = strrchr(fileName, '.');
	if (access(fileName, X_OK) < 0 && ext == 0) {
		ep = (MprStringData*) extList.getFirst();
		while (ep) {
			mprSprintf(pathBuf, sizeof(pathBuf), "%s%s", fileName, ep->string);
			if (access(pathBuf, X_OK) == 0) {
				break;
			}
			ep = (MprStringData*) extList.getNext(ep);
		}
		if (ep) {
			ext = ep->string;
		} else {
			mprStrcpy(pathBuf, sizeof(pathBuf), fileName);
		}

	} else {
		mprStrcpy(pathBuf, sizeof(pathBuf), fileName);
	}

	if (ext && (strcmp(ext, ".bat") == 0 || strcmp(ext, ".cmd") == 0)) {
		//
		//	Let a mime action override COMSPEC
		//
		if (actionProgram) {
			cmdShell = actionProgram;
		} else {
			cmdShell = getenv("COMSPEC");
		}
		if (cmdShell == 0) {
			cmdShell = "cmd.exe";
		}
		*script = mprStrdup(pathBuf);
		*program = mprStrdup(cmdShell);
		return;
	}

	if (rq->openDoc(pathBuf) >= 0) {
		if (rq->readDoc(buf, MPR_MAX_FNAME) > 0) {
			rq->closeDoc();
			buf[MPR_MAX_FNAME] = '\0';
			if (buf[0] == '#' && buf[1] == '!') {
				cmdShell = mprStrTok(&buf[2], " \t\r\n", &tok);
				if (cmdShell[0] != '/' && 
						(cmdShell[0] != '\0' && cmdShell[1] != ':')) {
					//
					//	If we can't access the command shell and the command 
					//	is not an absolute path, look in the same directory 
					//	as the script.
					//
					if (access(cmdShell, X_OK) < 0) {
						mprGetDirName(dirBuf, sizeof(dirBuf), pathBuf);
						mprSprintf(tmp, sizeof(tmp), "%s/%s", dirBuf, cmdShell);
						cmdShell = tmp;
					}
				}
				if (actionProgram) {
					*program = mprStrdup(actionProgram);
				} else {
					*program = mprStrdup(cmdShell);
				}
				*bangScript = mprStrdup(pathBuf);
				return;
			}
		} else {
			rq->closeDoc();
		}
	}

	if (actionProgram) {
		*program = mprStrdup(actionProgram);
		*bangScript = mprStrdup(pathBuf);
	} else {
		*program = mprStrdup(pathBuf);
	}
	return;
}
 
#endif
////////////////////////////////////////////////////////////////////////////////
#else 
void mprCgiHandlerDummy() {}

#endif // BLD_FEATURE_CGI_MODULE

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
