///
///	@file 	compatModule.cpp
/// @brief 	Compatibility module for the GoAhead Web Server
///
///	Provide a measure of compatibility with the common GoAhead WebServer
///	APIs.
///
///	@remarks This module only supports single threaded operation without 
///	any support for virtual hosts.
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	Portions Copyright (c) GoAhead Software Inc., 1998-2000.
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

#include	"compatModule.h"

//////////////////////////////////// Locals ////////////////////////////////////
#if BLD_FEATURE_COMPAT_MODULE

#define MPR_HTTP_MAX_GO_FORM		100
#define MPR_HTTP_MAX_ASP			100

static MprFile 		*file;
static MaServer		*defaultServer;
static MaHost		*defaultHost;
static WebsForm		*websForms[MPR_HTTP_MAX_GO_FORM];
static int 			maxForm;
static WebsAsp		*websAsp[MPR_HTTP_MAX_ASP];
static int			maxAsp;

class SymHashEntry : public MprHashEntry {
  public:
	sym_t			sym;
					SymHashEntry(char *key, value_t *vp);
	virtual			~SymHashEntry();
	value_t			*getValue() { return &sym.content; };
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// CompatModule /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int mprCompatInit(void *handle)
{
	if (maGetHttp() == 0) {
		return MPR_ERR_NOT_INITIALIZED;
	}
	new MaCompatModule(handle);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MaCompatModule::MaCompatModule(void *handle) : MaModule("compat", handle)
{
	file = new MprFile();
}

////////////////////////////////////////////////////////////////////////////////

MaCompatModule::~MaCompatModule()
{
	//
	//	No need to delete websForms[]. EgiHandler will delete these for us
	//
	delete file;
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// WebsForm ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

WebsForm::WebsForm(char *formName, WebsFormCb fn) : MaEgiForm(formName)
{
	goFormCallback = fn;
}

////////////////////////////////////////////////////////////////////////////////

WebsForm::~WebsForm()
{
}

////////////////////////////////////////////////////////////////////////////////

void WebsForm::run(MaRequest *rq, char *script, char *uri, char *query, 
	char *postData, int postLen)
{
	//
	//	GoAhead GoForms write their own headers
	//
	rq->setHeaderFlags(MPR_HTTP_HEADER_WRITTEN);
#if BLD_FEATURE_KEEP_ALIVE
	rq->setNoKeepAlive();
#endif
	//
	//	This will stop EGI from closing the socket
	//
	rq->setFlags(MPR_HTTP_DONT_AUTO_FINISH, -1);

	(*goFormCallback)((webs_t) rq, uri, query);
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// WebsAsp ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

WebsAsp::WebsAsp(char *name, WebsAspCb fn) : MaEspProc(name)
{
	aspCallback = fn;
}

////////////////////////////////////////////////////////////////////////////////

WebsAsp::~WebsAsp()
{
}

////////////////////////////////////////////////////////////////////////////////

int WebsAsp::run(MaRequest *rq, int argc, char **argv)
{
	return (*aspCallback)((int) getScriptEngine(), (webs_t) rq, argc, argv);
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// C APIs ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
extern "C" {

char_t *strlower(char_t *string)
{
	char_t	*s;

	a_assert(string);

	if (string == NULL) {
		return NULL;
	}

	s = string;
	while (*s) {
		if (isupper(*s)) {
			*s = (char_t) tolower(*s);
		}
		s++;
	}
	*s = '\0';
	return string;
}

////////////////////////////////////////////////////////////////////////////////

char_t *strupper(char_t *string)
{
	char_t	*s;

	a_assert(string);
	if (string == NULL) {
		return NULL;
	}

	s = string;
	while (*s) {
		if (islower(*s)) {
			*s = (char_t) toupper(*s);
		}
		s++;
	}
	*s = '\0';
	return string;
}

////////////////////////////////////////////////////////////////////////////////

value_t valueInteger(long value)
{
	value_t	v;

	memset(&v, 0x0, sizeof(v));
	v.valid = 1;
	v.type = integer;
	v.value.integer = value;
	return v;
}

////////////////////////////////////////////////////////////////////////////////

value_t valueString(char_t* value, int flags)
{
	value_t	v;

	memset(&v, 0x0, sizeof(v));
	v.valid = 1;
	v.type = string;
	if (flags & VALUE_ALLOCATE) {
		v.allocated = 1;
		v.value.string = bstrdup(B_L, value);
	} else {
		v.allocated = 0;
		v.value.string = value;
	}
	return v;
}

////////////////////////////////////////////////////////////////////////////////

int emfSchedCallback(int delay, emfSchedProc *proc, void *arg)
{
	new MprTimer(delay, (MprTimerProc) proc, (void*) arg, 
		MPR_TIMER_AUTO_RESCHED);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void emfUnschedCallback(int id)
{
	MprTimer	*timer;

	timer = (MprTimer*) id;
	timer->stop(1000);
	timer->dispose();
}

////////////////////////////////////////////////////////////////////////////////

void emfReschedCallback(int id, int delay)
{
	MprTimer	*timer;

	timer = (MprTimer*) id;
	timer->reschedule(delay);
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// SymHashEntry /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

SymHashEntry::SymHashEntry(char *key, value_t *vp) : MprHashEntry(key)
{
	sym.forw = 0;
	sym.name.value.string = key;
	sym.name.type = string;
	sym.arg = 0;

	sym.content = *vp;
	if (vp->allocated) {
		sym.content.value.string = mprStrdup(vp->value.string);
	}
}

////////////////////////////////////////////////////////////////////////////////

SymHashEntry::~SymHashEntry()
{
	if (sym.content.allocated) {
		mprFree(sym.content.value.string);
	}
}

////////////////////////////////////////////////////////////////////////////////

sym_fd_t symOpen(int tableSize)
{
	return (sym_fd_t) new MprHashTable();
}

////////////////////////////////////////////////////////////////////////////////

void symClose(sym_fd_t sd)
{
	MprHashTable	*table = (MprHashTable*) sd;

	delete table;
}

////////////////////////////////////////////////////////////////////////////////

sym_t *symLookup(sym_fd_t sd, char_t *name)
{
	MprHashTable	*table = (MprHashTable*) sd;
	SymHashEntry	*sp;

	sp = (SymHashEntry*) table->lookup(name);
	if (sp == 0) {
		return 0;
	}
	return &sp->sym;
}

////////////////////////////////////////////////////////////////////////////////

sym_t *symEnter(sym_fd_t sd, char_t *name, value_t v, int arg)
{
	MprHashTable	*table = (MprHashTable*) sd;
	SymHashEntry	*sp;

	sp = new SymHashEntry(name, &v);
	table->insert(sp);
	return &sp->sym;
}

////////////////////////////////////////////////////////////////////////////////

int symDelete(sym_fd_t sd, char_t *name)
{
	MprHashTable	*table = (MprHashTable*) sd;
	SymHashEntry	*sp;

	sp = (SymHashEntry*) table->lookup(name);
	if (sp) {
		table->remove(sp);
		delete sp;
		return 0;
	} else {
		return -1;
	}
}

////////////////////////////////////////////////////////////////////////////////

sym_t *symFirstEx(sym_fd_t sd, void **current)
{
	MprHashTable	*table = (MprHashTable*) sd;
	SymHashEntry	*sp;

	sp = (SymHashEntry*) table->getFirst();
	if (sp == 0) {
		return 0;
	}
	* ((SymHashEntry**) current) = sp;
	return &sp->sym;
}

////////////////////////////////////////////////////////////////////////////////

sym_t *symNextEx(sym_fd_t sd, void **current)
{
	MprHashTable	*table = (MprHashTable*) sd;
	SymHashEntry	*sp;

	sp = (SymHashEntry*) table->getNext((SymHashEntry*) *current);
	if (sp == 0) {
		return 0;
	}
	* ((SymHashEntry**) current) = sp;
	return &sp->sym;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Replicate this inline as it is hard to map varargs functions
//

int ejArgs(int argc, char_t **argv, char_t *fmt, ...)
{
	va_list		vargs;
	char		*cp, **sp;
	int			*ip;
	int			argn;

	va_start(vargs, fmt);

	if (argv == 0) {
		return 0;
	}

	for (argn = 0, cp = fmt; argn < argc && cp && *cp && argv[argn]; ) {
		if (*cp++ != '%') {
			continue;
		}

		switch (*cp) {
		case 'd':
			ip = va_arg(vargs, int*);
			*ip = atoi(argv[argn]);
			break;

		case 's':
			sp = va_arg(vargs, char**);
			*sp = argv[argn];
			break;

		default:
			mprAssert(0);
		}
		argn++;
	}

	va_end(vargs);
	return argn;
}

////////////////////////////////////////////////////////////////////////////////

void ejSetResult(int eid, char_t *s) 
{
	((MprEjs*) eid)->setResult(s);
}

////////////////////////////////////////////////////////////////////////////////

void ejSetVar(int eid, char_t *var, char_t *value)
{
	((MprEjs*) eid)->setVar(var, value);
}

////////////////////////////////////////////////////////////////////////////////

int umOpen() 
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void umClose() 
{
}

////////////////////////////////////////////////////////////////////////////////

int umRestore(char_t *filename)
{
#if FUTURE
	auth->resetUserGroup();
	auth->readGroupFile(server, auth, filename);
	auth->readUserFile(server, auth, filename);
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umCommit(char_t *filename)
{
#if FUTURE
	auth->save(filename);
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umAddGroup(char_t *group, short privilege, accessMeth_t am, 
	bool_t protect, bool_t disabled)
{
#if FUTURE
	//
	//	protected == delete protected. This should be done in the UI anyway.
	//	accessMethod == noAuth, basic, digest
	//	disabled == enable the user
	//
	auth->createGroup(group);
	
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umAddUser(char_t *user, char_t *password, char_t *group, bool_t protect, 
	bool_t disabled)
{
#if FUTURE
	//	not supporting disabled, protect
	auth->addUserPassword(user, password);
	auth->addUsersToGroup(group, user);
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umDeleteGroup(char_t *group)
{
#if FUTURE
	auth->removeGroup(group);
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umDeleteUser(char_t *user)
{
#if FUTURE
	auth->removeUser(user);
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

char_t *umGetFirstGroup()
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

char_t *umGetNextGroup(char_t *lastUser)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

char_t *umGetFirstUser()
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

char_t *umGetNextUser(char_t *lastUser)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

accessMeth_t umGetGroupAccessMethod(char_t *group)
{
	return AM_NONE;
}

////////////////////////////////////////////////////////////////////////////////

bool_t umGetGroupEnabled(char_t *group)
{
	return 1;
}

////////////////////////////////////////////////////////////////////////////////

short umGetGroupPrivilege(char_t *group)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

bool_t umGetUserEnabled(char_t *user)
{
	return 1;
}

////////////////////////////////////////////////////////////////////////////////

char_t *umGetUserGroup(char_t *user)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

char_t *umGetUserPassword(char_t *user)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

bool_t umGroupExists(char_t *group)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umSetGroupAccessMethod(char_t *group, accessMeth_t am)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umSetGroupEnabled(char_t *group, bool_t enabled)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umSetGroupPrivilege(char_t *group, short privileges)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umSetUserEnabled(char_t *user, bool_t enabled)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umSetUserGroup(char_t *user, char_t *password)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int umSetUserPassword(char_t *user, char_t *password)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

bool_t umUserExists(char_t *user)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int websAspDefine(char_t *name, WebsAspCb fn)
{
	if (maxAsp >= MPR_HTTP_MAX_ASP) {
		mprError(MPR_L, MPR_LOG, "Too many ASP procedures");
		return -1;
	}
	websAsp[maxAsp++] = new WebsAsp(name, fn);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void websDecodeUrl(char_t *decoded, char *token, int len)
{
	maDescapeUri(decoded, len, token);
}

////////////////////////////////////////////////////////////////////////////////

void websDone(webs_t wp, int code)
{
	bool	closeSocket;

	closeSocket = 1;
	((MaRequest*) wp)->finishRequest(code, closeSocket);
}

////////////////////////////////////////////////////////////////////////////////

void websError(webs_t wp, int code, char_t *msg, ...)
{
	va_list		ap;
	char		buf[MPR_MAX_STRING];

	va_start(ap, msg);
	mprVsprintf(buf, sizeof(buf), msg, ap);
	((MaRequest*) wp)->requestError(code, buf);
	va_end(ap);
}

////////////////////////////////////////////////////////////////////////////////

char_t *websErrorMsg(int code)
{
	return maGetHttpErrorMsg(code);
}

////////////////////////////////////////////////////////////////////////////////

void websFooter(webs_t wp)
{
	((MaRequest*) wp)->write("</html>\n");
}

////////////////////////////////////////////////////////////////////////////////

int websFormDefine(char_t *name, WebsFormCb fn)
{
	char	nameBuf[MPR_HTTP_MAX_URL];

	if (maxForm >= MPR_HTTP_MAX_GO_FORM) {
		mprError(MPR_L, MPR_LOG, "Too many goForms");
		return -1;
	}
	mprSprintf(nameBuf, sizeof(nameBuf), "/goform/%s", name);
	websForms[maxForm++] = new WebsForm(nameBuf, fn);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

char_t *websGetDateString(websStatType *sbuf)
{
	MprFileInfo		info;

	info.mtime = sbuf->mtime;
	return maGetDateString(&info);
}

////////////////////////////////////////////////////////////////////////////////

char_t *websGetRequestLpath(webs_t wp)
{
	return ((MaRequest*) wp)->getFileName();
}

////////////////////////////////////////////////////////////////////////////////

char_t *websGetVar(webs_t wp, char_t *var, char_t *def)
{
	return ((MaRequest*) wp)->getVar(var, def);
}

////////////////////////////////////////////////////////////////////////////////

void websHeader(webs_t wp)
{
	MaRequest	*rq = (MaRequest*) wp;

	rq->write("HTTP/1.0 200 OK\r\n");
	rq->writeFmt("Server: %s\r\n", MPR_HTTP_SERVER_NAME);
	rq->write("Pragma: no-cache\r\n");
	rq->write("Cache-control: no-cache\r\n");
	rq->write("Content-Type: text/html\r\n");
	rq->write("\r\n");
	rq->write("<html>\r\n");
}

////////////////////////////////////////////////////////////////////////////////

int websPageOpen(webs_t wp, char_t *fileName, char_t *uri, int mode, int perm)
{
	MaRequest		*rq;
 
	rq = (MaRequest*) wp;
	return file->open(uri, mode, perm);
}

////////////////////////////////////////////////////////////////////////////////

int websPageStat(webs_t wp, char_t *fileName, char_t *uri, websStatType* sbuf)
{
	MaRequest		*rq;
	MprFileInfo		info;
 
	rq = (MaRequest*) wp;
	if (rq->host->server->fileSystem->stat(uri, &info) < 0) {
		return MPR_ERR_CANT_ACCESS;
	}
	sbuf->size = info.size;
	sbuf->isDir = info.isDir;
	sbuf->mtime = info.mtime;
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void websRedirect(webs_t wp, char_t *url)
{
	((MaRequest*) wp)->redirect(301, url);
	((MaRequest*) wp)->flushOutput(MPR_HTTP_FOREGROUND_FLUSH, 
		MPR_HTTP_FINISH_REQUEST);
}

////////////////////////////////////////////////////////////////////////////////

void websSetRealm(char_t *realmName)
{
	MaDir		*dir;
	MaAuth		*auth;

	if (defaultServer == 0) {
		defaultServer = maGetHttp()->findServer("default");
		defaultHost = defaultServer->getDefaultHost();
	}
	if (defaultServer == 0 || defaultHost == 0) {
		mprError(MPR_L, MPR_LOG, "Undefined server or host");
		return;
	}
	dir = defaultHost->findBestDir(defaultServer->getServerRoot());

	if (dir == 0) {
		mprError(MPR_L, MPR_LOG, 
			"websSetRealm Error: Server not yet configured");
		return;
	}

	auth = dir->getAuth();
	mprAssert(auth);
	if (auth == 0) {
		mprError(MPR_L, MPR_LOG, 
			"webSetRealm Error: Server not yet configured");
		return;
	}

	auth->setRealm(realmName);
}

////////////////////////////////////////////////////////////////////////////////

void websSetRequestLpath(webs_t wp, char_t *fileName)
{
	((MaRequest*) wp)->setFileName(fileName);
}

////////////////////////////////////////////////////////////////////////////////

int websUrlHandlerDefine(char_t *urlPrefix, char_t *webDir, int arg, 
	int (*fn)(webs_t wp, char_t *urlPrefix, char_t *webDir, int arg, 
	char_t *url, char_t *path, char_t *query), int flags)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int websValid(webs_t wp)
{
	//
	//	Always return valid. Hope this is sufficient
	//
	return 1;
}

////////////////////////////////////////////////////////////////////////////////

int websValidateUrl(webs_t wp, char_t *path)
{
	if (maValidateUri(path) == 0) {
		return -1;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int websWrite(webs_t wp, char_t* fmt, ...)
{
	va_list		ap;
	char		buf[MPR_MAX_STRING];

	va_start(ap, fmt);
	mprVsprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	return ((MaRequest*) wp)->write(buf);
}

////////////////////////////////////////////////////////////////////////////////

int websWriteBlock(webs_t wp, char_t *buf, int nChars)
{
	return ((MaRequest*) wp)->write(buf, nChars);
}

////////////////////////////////////////////////////////////////////////////////
}	// extern "C"
#else
void mprCompatModuleDummy() {}

#endif // BLD_FEATURE_COMPAT_MODULE

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
