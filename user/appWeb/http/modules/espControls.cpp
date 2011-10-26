///
///	@file 	espControls.cpp
/// @brief 	Embedded Server Pages (ESP) Controls.
///
///	These javascript procedures can be used in ESP pages for common tasks.
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

int MaEspHandlerService::startControls()
{
	if (nextProc >= maxProc) {
		maxProc += 16;
		standardProcs = (MaEspProc**) mprRealloc((void*) standardProcs, 
			sizeof(MaEspProc*) * maxProc);
	}
	standardProcs[nextProc++] = new MaEspWrite();
	standardProcs[nextProc++] = new MaEspInclude();
	standardProcs[nextProc++] = new MaEspRedirect();
	standardProcs[nextProc++] = new MaEspTabs();

#if BLD_FEATURE_SESSION
	standardProcs[nextProc++] = new MaEspCreateSession();
	standardProcs[nextProc++] = new MaEspDestroySession();
	standardProcs[nextProc++] = new MaEspGetSessionData();
	standardProcs[nextProc++] = new MaEspGetSessionId();
	standardProcs[nextProc++] = new MaEspSetSessionData();
	standardProcs[nextProc++] = new MaEspTestSessionData();
	standardProcs[nextProc++] = new MaEspUnsetSessionData();
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaEspWrite //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Esp write command. This implemements <% write("text"); %> command
//	FUTURE -- move to separate loadable module when we have more commands
// 

int MaEspWrite::run(MaRequest *rq, int argc, char **argv)
{
	MaDataStream	*dynBuf;
	char			*s;
	int				i;

	dynBuf = rq->getDynBuf();

	mprAssert(argv);
	for (i = 0; i < argc; ) {
		s = argv[i];
		rq->writeBlk(dynBuf, s, strlen(s));
		if (++i < argc) {
			rq->writeBlk(dynBuf, " ", 1);
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaEspRedirect ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Esp redirect command. This implemements <% redirect(url, code); %> command
//	The redirection code is optional.
// 

int MaEspRedirect::run(MaRequest *rq, int argc, char **argv)
{
	char	*url;
	int		code;

	if (argc < 1) {
		setError("Bad args");
		return MPR_ERR_BAD_ARGS;
	}
	url = argv[0];
	if (argc == 2) {
		code = atoi(argv[1]);
	} else {
		code = 302;
	}
	rq->redirect(code, url);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaEspInclude /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Esp include command. This implemements server-side includes. I.e.
//		<% include("file", ...); %> 
//	Filenames are relative to the base document including the file.
// 

int MaEspInclude::run(MaRequest *rq, int argc, char **argv)
{
	MaDataStream	*dynBuf;
	MprFileInfo		info;
	MprFileSystem	*fs;
	MprFile			file;
	char			path[MPR_MAX_FNAME], tmp[MPR_MAX_FNAME], dir[MPR_MAX_FNAME];
	char			*s, *emsg, *buf;
	int				i;

	dynBuf = rq->getDynBuf();
	fs = rq->host->server->fileSystem;

	mprAssert(argv);
	for (i = 0; i < argc; i++) {
		s = argv[i];

		//
		//	Prepend the directory of the base document and then validate to 
		//	prevent ".." out of the DocumentRoot.
		//
		mprGetDirName(dir, sizeof(dir), rq->getUri());
		mprSprintf(tmp, sizeof(tmp), "%s/%s", dir, argv[i]);
		maValidateUri(tmp);
		
		if (rq->host->mapToStorage(rq, tmp, path, sizeof(path), 0) < 0) {
			setError("Can't map include file to storage");
			return MPR_ERR_CANT_ACCESS;
		}
		if (fs->stat(path, &info) < 0) {
			setError("Can't stat include file");
			return MPR_ERR_CANT_ACCESS;
		}
		if (file.open(path, O_RDONLY, 0666) < 0) {
			setError("Can't open include file");
			return MPR_ERR_CANT_OPEN;
		}
		buf = (char*) mprMalloc(info.size + 1);
		if (file.read(buf, info.size) < 0) {
			mprFree(buf);
			return MPR_ERR_CANT_READ;
		}
		buf[info.size] = '\0';
		file.close();

		if (scriptEngine->evalScript(buf, &emsg) < 0) {
			setError("Cant evaluate script");
			mprFree(buf);
			return -1;
		}
		mprFree(buf);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Session Controls ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_SESSION

int MaEspCreateSession::run(MaRequest *rq, int argc, char **argv)
{
	int		timeout;

	if (argc > 1) {
		setError("Bad args");
		return MPR_ERR_BAD_ARGS;

	} else if (argc == 1) {
		timeout = atoi(argv[0]);
	} else {
		timeout = 0;
	}
	
	rq->createSession(timeout);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspDestroySession::run(MaRequest *rq, int argc, char **argv)
{
	rq->destroySession();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspGetSessionData::run(MaRequest *rq, int argc, char **argv)
{
	char	*value, *defaultValue;

	if (argc < 1 || argc > 2) {
		setError("Bad args");
		return MPR_ERR_BAD_ARGS;
	}

	if (argc == 2) {
		defaultValue = argv[1];
	} else {
		defaultValue = "";
	}
	value = rq->getSessionData(argv[0], defaultValue);
	setResult(value);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspGetSessionId::run(MaRequest *rq, int argc, char **argv)
{
	setResult(rq->getSessionId());
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspSetSessionData::run(MaRequest *rq, int argc, char **argv)
{
	if (argc < 2) {
		setError("Bad args");
		return MPR_ERR_BAD_ARGS;
	}

//	mprLog(3, "setSessionData: %s <= %s\n", argv[0], argv[1]);
	rq->setSessionData(argv[0], argv[1]);
	setResult(argv[1]);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspTestSessionData::run(MaRequest *rq, int argc, char **argv)
{
	if (argc < 1) {
		setError("Bad args");
		return MPR_ERR_BAD_ARGS;
	}

	if (rq->getSessionData(argv[0], 0) == 0) {
		setResult("0");
	} else {
		setResult("1");
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaEspUnsetSessionData::run(MaRequest *rq, int argc, char **argv)
{
	if (argc < 1) {
		setError("Bad args");
		return MPR_ERR_BAD_ARGS;
	}

	if (rq->unsetSessionData(argv[0]) < 0) {
		setResult("-1");
	} else {
		setResult("0");
	}
	return 0;
}

#endif	// BLD_FEATURE_SESSION
////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// Tabs Control /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Usage:
//		esp:tabs "Tab Names" "Urls" "Target Frame"
//

int MaEspTabs::run(MaRequest *rq, int argc, char **argv)
{
	char	*namesArg, *urlsArg, *targetArg, *c, *query;
	int		i;

	query = rq->getQueryString();
	targetArg = "viewPane";

	if (mprParseArgs(argc, argv, "%s %s %s", &namesArg, &urlsArg, 
			&targetArg) < 2) {
		setError("Bad args");
		return -1;
	}

	MprStringList names(namesArg);
	MprStringList urls(urlsArg);

	if (names.getNumItems() != urls.getNumItems() || names.getNumItems() < 1) {
		setError("Bad number of URLs");
		return -1;
	}

	rq->write("<table border=0 cellpadding=0 cellspacing=0>\n<tr>\n");

	MprStringData	*namep, *urlp;
	namep = (MprStringData*) names.getFirst();
	urlp = (MprStringData*) urls.getFirst();

	i = 0;
	while (namep) {
		rq->writeFmt("\t<td id=tabl%d class=dividerTab>"
			"<img src=/images/tabl.gif></td>\n", i);
		rq->writeFmt("\t<td id=tab%d class=tab>\n", i);
		while ((c = strchr(namep->getValue(), '_')) != NULL) {
			*c = ' ';
		}
		if (strcmp(urlp->getValue(), "_null") != 0) {
			rq->writeFmt("\t\t<a id=taba%d href='%s?%s' \
				target='%s' onClick='return selectTab(%d);'>%s</a>\n", 
				i, urlp->getValue(), query, targetArg, i, namep->getValue());
		} else {
			rq->writeFmt("\t\t<font class=tabLinkDisabled>%s</font>\n", 
				namep->getValue());
		}
		rq->writeFmt("\t</td>\n"
			"\t<td id=tabr%d class=dividerTab>"
			"<img src=/images/tabr.gif></td>\n", i);
		i++;
		namep = (MprStringData*) names.getNext(namep);
		urlp = (MprStringData*) urls.getNext(urlp);
	}
	rq->writeFmt("</tr>\n</table>\n<script language=JavaScript>\n"
		"initTabs(%d);\n", names.getNumItems());
	rq->write("</script>\n</body></html>\n");

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#else
void mprEspControlsDummy() {}

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
