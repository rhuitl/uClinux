///
///	@file 	espHandler.cpp
/// @brief 	Embedded Server Pages (ESP) handler.
///
///	The ESP handler provides an efficient way to generate dynamic pages using
///	server-side Javascript.
///
///	The ESP module processes ESP pages and executes embedded scripts. It 
///	supports an open scripting architecture for a variety of scripting services.
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

#include	"espHandler.h"

//////////////////////////////////// Locals ////////////////////////////////////
#if BLD_FEATURE_ESP_MODULE
//
//	Local to make it easier for EspProc to access
//

static MaEspHandlerService *espService;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaEspModule /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int mprEspInit(void *handle)
{
	if (maGetHttp() == 0) {
		return MPR_ERR_NOT_INITIALIZED;
	}
	new MaEspModule(handle);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MaEspModule::MaEspModule(void *handle) : MaModule("esp", handle)
{
	espService = new MaEspHandlerService();
}

////////////////////////////////////////////////////////////////////////////////

MaEspModule::~MaEspModule()
{
	delete espService;
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////// MaEspHandlerService //////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaEspHandlerService::MaEspHandlerService() : MaHandlerService("espHandler")
{
	nextProc = maxProc = 0;
	standardProcs = 0;
	procs = new MprHashTable(53);

#if BLD_FEATURE_LOG
	log = new MprLogModule("esp");
#endif
#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaEspHandlerService::~MaEspHandlerService()
{
	mprFree(standardProcs);
	delete procs;

#if BLD_FEATURE_LOG
	delete log;
#endif
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
}

////////////////////////////////////////////////////////////////////////////////

int MaEspHandlerService::start()
{
	startControls();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MaHandler *MaEspHandlerService::newHandler(MaServer *server, MaHost *host, 
	char *extensions)
{
	MaEspHandler	*ep;

	//
	//	Currently only a single procs hash table for all servers/hosts
	//
	ep = new MaEspHandler(extensions, log, procs);
	return ep;
}

////////////////////////////////////////////////////////////////////////////////

void MaEspHandlerService::insertProc(MaServer *server, MaHost *host, 
	MaEspProc *proc)
{
	procs->insert(proc);
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaEspHandler /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaEspHandler::MaEspHandler(char *extensions, MprLogModule *serviceLog, 
	MprHashTable *procTable) :
		MaHandler("espHandler", extensions, 
		MPR_HANDLER_GET | MPR_HANDLER_POST | 
		MPR_HANDLER_NEED_ENV | MPR_HANDLER_TERMINAL)
{
	log = serviceLog;

	//
	//	Cloned handlers (per-request) use the master instance procs table
	//
	if (procTable == 0) {
		mprAssert(0);
		procs = new MprHashTable(53);
	} else {
		this->procs = procTable;
	}

	engine = 0;
	espFlags = 0;
	postBuf = 0;
}

////////////////////////////////////////////////////////////////////////////////
 
MaEspHandler::~MaEspHandler()
{
	if (engine) {
		delete engine;
	}
	delete postBuf;
}

////////////////////////////////////////////////////////////////////////////////

MaHandler *MaEspHandler::cloneHandler()
{
	MaEspHandler	*ep;

	ep = new MaEspHandler(extensions, log, procs);
	ep->flags |= MPR_ESP_CLONED;
	return ep;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspHandler::setup(MaRequest *rq)
{
	MaLimits	*limits;

	limits = rq->host->getLimits();
	mprAssert(postBuf == 0);
	postBuf = new MprBuf(MPR_HTTP_IN_BUFSIZE, limits->maxBody);
	mprLog(5, log, "%d: setup\n", rq->getFd());
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Read all post data and convert to variables. But only if urlencoded.
//

void MaEspHandler::postData(MaRequest *rq, char *buf, int len)
{
	int		rc;

	mprLog(5, log, "%d: postData %d bytes\n", rq->getFd(), len);

	if (len < 0 && rq->getRemainingContent() > 0) {
		rq->requestError(400, "Incomplete post data");
		return;
	}

	rc = postBuf->put((uchar*) buf, len);
	postBuf->addNull();

	if (rc != len) {
		rq->requestError(MPR_HTTP_REQUEST_TOO_LARGE, "Too much post data");

	} else {
		//
		//	If we have all the post data, convert it into vars and call the 
		//	run method.
		//
		if (rq->getRemainingContent() <= 0) {
			mprLog(4, log, "%d: Post Data: length %d\n< %s\n", rq->getFd(), 
				postBuf->getLength(), postBuf->getStart());
			rq->createEnvVars(postBuf->getStart(), postBuf->getLength());
			run(rq);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////

MprBuf *MaEspHandler::getPostBuf()
{
	return postBuf;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspHandler::run(MaRequest *rq)
{
	MaDataStream	*dynBuf;
	MaHeader		*header;
	char			*fileName;
	int				flags, contentLength;

	flags = rq->getFlags();

	if (flags & MPR_HTTP_POST_REQUEST && rq->getRemainingContent() > 0) {
		//
		//	When all the post data is received the run method will be recalled
		//	by the postData method.
		//
		header = rq->getHeader();
		if (mprStrCmpAnyCase(header->contentMimeType, 
				"application/x-www-form-urlencoded") != 0) {
			rq->requestError(MPR_HTTP_UNSUPPORTED_MEDIA_TYPE, 
				"Post data is not urlencoded");
		}
		return MPR_HTTP_HANDLER_FINISHED_PROCESSING;
	}

	hitCount++;
	dynBuf = rq->getDynBuf();

	rq->setResponseCode(200);
	rq->setResponseMimeType("text/html");
	rq->setHeaderFlags(MPR_HTTP_DONT_CACHE);

	fileName = rq->getFileName();

	if (rq->openDoc(fileName) < 0) {
		rq->requestError(404, "Can't open document: %s", fileName);
		return MPR_HTTP_HANDLER_FINISHED_PROCESSING;
	} 
	mprLog(4, log, "%d: serving: %s\n", rq->getFd(), fileName);

	if (flags & (MPR_HTTP_GET_REQUEST | MPR_HTTP_POST_REQUEST)) {
		rq->insertDataStream(dynBuf);
		if (process(rq) < 0) {
			// process() handles it's own errors
			return MPR_HTTP_HANDLER_FINISHED_PROCESSING;
		}
	}

	contentLength = dynBuf->buf.getLength();
	if (contentLength > 0) {
		dynBuf->setSize(contentLength);
	}

	rq->flushOutput(MPR_HTTP_BACKGROUND_FLUSH, MPR_HTTP_FINISH_REQUEST);
	return MPR_HTTP_HANDLER_FINISHED_PROCESSING;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspHandler::process(MaRequest *rq)
{
	MprFileInfo		*info;
	char			*fileName, *docBuf, *errMsg, *jsBuf;
	int				size, jsLen;

	fileName = rq->getFileName();
	info = rq->getFileInfo();

	size = info->size * sizeof(char);
	docBuf = (char*) mprMalloc(size + 1);
	docBuf[size] = '\0';

	if (rq->readDoc(docBuf, size) != size) {
		rq->requestError(404, "Can't read document");
		mprFree(docBuf);
		return MPR_ERR_CANT_READ;
	}

	jsBuf = 0;
	jsLen = 0;
	if (buildScript(rq, &jsBuf, &jsLen, docBuf) < 0) {
		mprFree(docBuf);
		return MPR_ERR_CANT_COMPLETE;
	}

	//
	//	Now evaluate the entire escript
	//
	mprLog(7, "ESP Script is:\n%s\n", jsBuf);
	if (jsLen > 0) {
		if (engine) {
			if (engine->evalScript(jsBuf, &errMsg) == 0) {
				if (errMsg) {
					rq->writeFmt("<h2><b>ESP Error: %s</b></h2>\n", errMsg);
					rq->writeFmt("<pre>%s</pre>", jsBuf);
					mprFree(errMsg);

				} else {
					rq->writeFmt("<h2><b>ESP Error</b></h2>\n%s\n", jsBuf);
				}
				rq->write("</body></html>\n");
			}
		} else {
			rq->write(docBuf);
		}
	}

	mprFree(docBuf);
	mprFree(jsBuf);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convert an ESP page into a JavaScript. We also expand include files.
//

int MaEspHandler::buildScript(MaRequest *rq, char **buf, int *lenp, char *input)
{
	MprFileInfo	info;
	MprFile		file;
	char		path[MPR_MAX_FNAME];
	char		*end, *cp, *quote, *atat, *incBuf;
	int			len, rc, saveChr;

	mprAssert(buf);
	mprAssert(lenp);

	rc = 0;
	len = *lenp;

	while (*input) {
		//
		//	Process HTML up to the first esp "<%" or "@@" tags, or quote
		//	"end" will point to the end of a block of pure text that doesn't
		//	require script processing.
		//
		end = strstr(input, "<%");
		if (end == 0) {
			end = &input[strlen(input)];
		}

		quote = strstr(input, "\"");
		if (quote && quote < end) {
			end = quote;
		} else {
			quote = 0;
		}

		atat = strstr(input, "@@");
		if (atat && atat < end && (isalnum(atat[2]) || atat[2] == '_') &&
				(atat == input || atat[-1] != '\\')) {
			end = atat;
			if (quote && quote < end) {
				end = quote;
			} else {
				quote = 0;
			}
		} else {
			atat = 0;
		}

		saveChr = *end;
		*end = '\0';
		if (quote) {
			len = mprReallocStrcat(buf, MPR_HTTP_MAX_RESPONSE_BODY, len, 0, 
				"write(\"", input, "\\\"\");\n", 0);
		} else {
			len = mprReallocStrcat(buf, MPR_HTTP_MAX_RESPONSE_BODY, len, 0, 
				"write(\"", input, "\");\n", 0);
		}
		*end = saveChr;
		if (quote) {
			input = end + 1;
			continue;
		}

		if (*end == '\0') {
			break;
		}

		//
		//	Process ESP directives: @@var, <% =var %>, <% code ... %>
		//
		if (atat) {
			if (engine == 0) {
				setScriptEngine(rq, "javascript");
				if (engine == 0) {
					rc = -1;
					break;
				}
			}
			input = atat + 2;
			end = input;
			while (*end && (isalnum(*end) || *end == '_' || *end == ':' || 
					*end == '.')) {
				end++;
			}

			saveChr = *end;
			*end = '\0';
			len = mprReallocStrcat(buf, MPR_HTTP_MAX_RESPONSE_BODY, len, 0, 
				"write(", input, ");\n", 0);
			*end = saveChr;
			input = end;

		} else {
			input = setScriptEngine(rq, skipSpace(end + 2));
			if (engine == 0) {
				rc = -1;
				break;
			}
			end = strstr(input, "%>");
			if (end == 0) {
				rc = -1;
				rq->requestError(500, "Unterminated ESP script");
				break;
			}
			if (input == end) {
				//	Script had just a language=javascript expression
				input += 2;
				continue;
			}
			if (*input == '=') {
				input = skipSpace(input + 1);
				cp = end - 1;
				while (isspace(*cp) && cp > input) {
					cp--;
				}
				cp++;
				if (*cp == '\0') {
					rc = -1;
					rq->requestError(500, "Missing ESP \"=\" variable");
					break;
				}
				saveChr = *end;
				*end = '\0';
				len = mprReallocStrcat(buf, MPR_HTTP_MAX_RESPONSE_BODY, len, 0, 
					"write(", input, ");\n", 0);
				*end = saveChr;

			} else {
				//
				//	Include directives or standard esp code sections
				//
				if (strncmp(input, "include", 7) == 0 && isspace(input[7])) {
					input = skipSpace(&input[7]);
					for (end = input; *end && !isspace(*end); ) {
						end++;
					} 
					saveChr = *end;
					*end = '\0';

					if (rq->host->mapToStorage(rq, input, path, 
							sizeof(path), 0) < 0) {
						rc = -1;
						rq->requestError(500, 
							"Can't map to storage for: %s", input);
						break;
					}
					if (rq->host->server->fileSystem->stat(path, &info) < 0 || 
							file.open(path, O_RDONLY, 0666) < 0) {
						rc = -1;
						rq->requestError(500, "Can't open: %s", path);
						break;
					}
					incBuf = (char*) mprMalloc(info.size + 1);
					if (file.read(incBuf, info.size) < 0) {
						file.close();
						mprFree(incBuf);
						rq->requestError(500, "Can't read: %s", path);
						rc = -1;
						break;
					}
					incBuf[info.size] = '\0';
					if (buildScript(rq, buf, &len, incBuf) < 0) {
						file.close();
						mprFree(incBuf);
						rc = -1;
						break;
					}
					file.close();
					mprFree(incBuf);
					*end = saveChr;
					end = skipSpace(end);

				} else {

					saveChr = *end;
					*end = '\0';
					len = mprReallocStrcat(buf, MPR_HTTP_MAX_RESPONSE_BODY, 
						len, 0, input, "\n", 0);
					*end = saveChr;
				}
			}
			input = end + 2;
		}
	}
	*lenp = len;
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

char *MaEspHandler::setScriptEngine(MaRequest *rq, char *tok)
{
	MprScriptService	*ss;
	char				*cp;
	char				name[MPR_MAX_FNAME];

	while (*tok && isspace(*tok)) {
		tok++;
	}
	cp = tok; 
	while (isalnum(*cp) || *cp == '=') {
		cp++;
	}
 
	if (cp > tok) {
		mprMemcpy(name, sizeof(name) - 1, tok, cp - tok);
	}
	name[cp - tok] = '\0';

	if (mprStrCmpAnyCaseCount("language=", name, 9) == 0) {
		tok += 9;
		ss = mprGetMpr()->lookupScriptService(&name[9]);
		if (ss == 0) {
			rq->requestError(500, "Unsupported script service");
			return tok;
		}
		if (engine) {
			delete engine;
		}
		engine = ss->newEngine((void*) rq, rq->getEnv(), procs);
		cp = skipSpace(tok + strlen(ss->getName()));
		if (*cp == ';') {
			cp++;
		}
		return skipSpace(cp);
	}
	if (engine == 0) {
		ss = mprGetMpr()->lookupScriptService("javascript");
		if (ss == 0) {
			rq->requestError(500, "No scripting service available");
			return tok;
		}
		engine = ss->newEngine(rq, rq->getEnv(), procs);
	}
	return tok;
}

////////////////////////////////////////////////////////////////////////////////

void MaEspHandler::insertProc(MaEspProc *proc)
{
	procs->insert(proc);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Skip white space
// 

char *MaEspHandler::skipSpace(char *s) 
{
	mprAssert(s);

	if (s == 0) {
		return s;
	}
	while (*s && isspace(*s)) {
		s++;
	}
	return s;
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaEspProc //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaEspProc::MaEspProc(char *name) : MprEjsProc(name)
{
	this->name = mprStrdup(name);
	espService->insertProc(0, 0, this);
}

////////////////////////////////////////////////////////////////////////////////

MaEspProc::MaEspProc(MaServer *server, MaHost *host, char *name) : 
	MprEjsProc(name)
{
	this->name = mprStrdup(name);
	espService->insertProc(server, host, this);
}

////////////////////////////////////////////////////////////////////////////////

MaEspProc::~MaEspProc()
{
	mprFree(name);
}

////////////////////////////////////////////////////////////////////////////////

char *MaEspProc::getName()
{
	return name;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspProc::run(void *userHandle, int argc, char **argv)
{
	return run((MaRequest*) userHandle, argc, argv);
}

////////////////////////////////////////////////////////////////////////////////

void MaEspProc::setResult(char *str)
{
	if (str == 0) {
		scriptEngine->setResult("");
	} else {
		scriptEngine->setResult(str);
	}
}

////////////////////////////////////////////////////////////////////////////////

void MaEspProc::setResultFmt(char *fmt, ...)
{
	va_list		args;
	char		*buf;

	va_start(args, fmt);
	mprAllocVsprintf(&buf, MPR_MAX_HEAP_SIZE, fmt, args);
	setResult(buf);
	mprFree(buf);
	va_end(args);
}

////////////////////////////////////////////////////////////////////////////////

void MaEspProc::setError(char *str)
{
	char	*escapeBuf;
	int		len;

	//
	//	Allow plenty of room for escaping HTML characters
	//
	len = strlen(str) * 3;
	escapeBuf = (char*) mprMalloc(len);
	maEscapeHtml(escapeBuf, len, str);

	scriptEngine->error(escapeBuf);
	mprFree(escapeBuf);
}

////////////////////////////////////////////////////////////////////////////////

void MaEspProc::setErrorFmt(char *fmt, ...)
{
	va_list		args;
	char		*buf;

	va_start(args, fmt);
	mprAllocVsprintf(&buf, MPR_MAX_HEAP_SIZE, fmt, args);
	setError(buf);
	mprFree(buf);
	va_end(args);
}

////////////////////////////////////////////////////////////////////////////////
#else
void mprEspHandlerDummy() {}

#endif // BLD_FEATURE_ESP_MODULE

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
