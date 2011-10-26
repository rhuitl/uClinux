///
///	@file 	ejs/ejsModule.cpp
/// @brief 	Enable Ejs to be used as a dynamically loadable module
///
///	@remarks This module is not thread-safe. It is the callers responsibility
///	to perform all thread synchronization.
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	Portions Copyright (c) GoAhead Software, 1995-2000. All Rights Reserved.
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

#include	"ejs.h"
 
//////////////////////////////////// Locals ////////////////////////////////////
#if BLD_FEATURE_EJS_MODULE

static MprEjsService	*jsService;

////////////////////////////// Forward Declarations ////////////////////////////

#if UNUSED
static void	jsSetEnvIntVar(char *var, int value);
static int	jsStrGetElement(int jsid, void *handle, int argc, char **argv);
static int	toUpperCase(int jsid, void *handle, int argc, char **argv);
static int	toLowerCase(int jsid, void *handle, int argc, char **argv);
static int	findPattern(int jsid, void *handle, int argc, char **argv);
static char *strGetElement(char *list, int n, char cc);
#endif

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MprEjsService /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprEjsService::MprEjsService() : MprScriptService("javascript")
{
	stndVars = (MprHashTable*) new MprHashTable(61);
	stndProcs = (MprHashTable*) new MprHashTable(61);

#if BLD_FEATURE_LOG
	logModule = new MprLogModule("JavaScript");
#endif

	//
	//	MOB -- this means only one service per app
	//
	jsService = this;
	configure();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Close this extension
// 

MprEjsService::~MprEjsService()
{
	delete stndVars;
	delete stndProcs;
#if BLD_FEATURE_LOG
	delete logModule;
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Initialize the js stndironment variables and functions
// 

int MprEjsService::configure()
{
	new MprEjsTraceProc(0, "trace");
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	This allows users of the MprEjsService to create engines in a virtualized way
//

MprScriptEngine *MprEjsService::newEngine(void *data, MprHashTable *vars, 
	MprHashTable *functions)
{
	MprEjs	*js;

	js = new MprEjs(this, vars, functions);
	js->setUserHandle(data);
	return js;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Define a standard function
// 

void MprEjsService::insertProc(MprEjsProc *proc)
{
	stndProcs->insert(proc);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Set a standard variable. Note: a variable with a value of NULL means
//	declared but undefined. The value is defined in the EJ stndironment, which
//	means it is accessible from all EJ spaces
// 

void MprEjsService::setStndVar(char *var, char *value)
{
	mprAssert(var && *var);

	stndVars->insert(new MprStringHashEntry(var, value));
}

////////////////////////////////////////////////////////////////////////////////
//
//	Trace to the log file.  Usage:
//
//	trace(message);
//	trace(level, message);
// 

int MprEjsTraceProc::run(void *handle, int argc, char **argv)
{
	MprEjs	*js;
	char	*cp;
	int		level;

	js = (MprEjs*) getScriptEngine();
	cp = argv[0];
	if (argc == 1) {
		level = 0;
	} else if (argc == 2) {
		level = atoi(cp);
		cp = argv[1];
	} else {
		mprError(MPR_L, MPR_LOG, "Usage: trace(message)");
		js->setResult("trace: Bad usage");
		return -1;
	}
#if BLD_FEATURE_LOG
	mprLog(level, js->jsService->logModule, "%s\n", cp);
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if UNUSED
//
//	Ejs wrapper for strGetElement
//	Args are:
//		string list
//		item number (0 is the first item)
//		character delimiter (if omitted, space is used)
//	Return value is the requested item in the list, or the delimiter
//	is returned if no value is found (equivalent of a NULL return in
//	strGetElement)
// 

static int jsStrGetElement(int jsid, void *handle, int argc, char **argv)
{
	char	*elem, c, s[2];

	if (argc < 2) {
		mprError(MPR_L, MPR_LOG, 
			"Usage: getElement(list, itemNum, delimiter);");
		return -1;
	}
	if (argc > 2) {
		c = *argv[2];
	} else {
		c = ' ';
	}

	elem = strGetElement(argv[0], atoi(argv[1]), c);
	if (elem != NULL) {
		gjSetResult(jsid, elem);
		mprFree(elem);
	} else {
		*s = c;
		s[1] = '\0';
		gjSetResult(jsid, s);
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Gets the n'th element in a comma delimited list.  List elements begin
//	numbering at zero.  Return value is a ptr to an allocated return
//	value, NULL if error. Caller must deallocate return value.
// 

static char *strGetElement(char *list, int n, char cc)
{
	char	*l, *r, *c;
	int		i;

	c = list;
	for (i = 0; i < n; i++) {
		c = strchr(c, cc);
		if (c == NULL) {
			return NULL;
		}
		c++;
	}
	l = c;
	c = strchr(l, cc);
	if (c == NULL) {
		i = strlen(l);
	} else {
		i = (c - l) / sizeof(char);
	}
	r = (char*) mprMalloc((i + 1) * sizeof(char));
	mprStrncpy(r, l, i);
	r[i] =  '\0';
	return r;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convert the input parameter to upper case
// 

static int toUpperCase(int jsid, void *handle, int argc, char **argv)
{
	char *temp;

	mprAssert(argv && *argv);

	if (argc != 1) {
		mprError(MPR_L, MPR_LOG,
			"Usage: jsConvertToUpperCase(string);");
		return -1;
	}

	//
	//	Use a temporary string because we don't want to modify the input var
	// 
	temp = mprStrdup(*argv);
	gjSetResult(jsid, mprStrupper(temp));
	mprFree(temp);

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convert the input parameter to all lower case
// 

static int toLowerCase(int jsid, void *handle, int argc, char **argv)
{
	char	*temp;

	mprAssert(argv && *argv);

	if (argc != 1) {
		mprError(MPR_L, MPR_LOG, "Usage: jsConvertToLowerCase(string);");
		return -1;
	}

	//
	//	Use a temporary string because we don't want to modify the input var
	// 
	temp = mprStrdup(*argv);
	gjSetResult(jsid, mprStrlower(temp));
	mprFree(temp);

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Function to find a substring within a string.  First parameter is
//	string to search.  Second parameter is the substring to search for.
//	Returns a boolean to indicate whether or not the string was found.
// 

static int findPattern(int jsid, void *handle, int argc, char **argv)
{
	mprAssert(argv);

	if (argc != 2) {
		mprError(MPR_L, MPR_LOG, "Usage: jsFindPattern(string, pattern);");
		return -1;
	}

	if (strstr(argv[0], argv[1]) != NULL) {
		gjSetResult(jsid, "1");
	} else {
		gjSetResult(jsid, "0");
	}

	return 0;
}

#endif
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MprEjsProc ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprEjsProc::MprEjsProc(char *name) : MprHashEntry(name)
{
	scriptEngine = 0;
	this->name = mprStrdup(name);
}

////////////////////////////////////////////////////////////////////////////////

MprEjsProc::MprEjsProc(MprEjs *js, char *name) : MprHashEntry(name)
{
	scriptEngine = js;
	this->name = mprStrdup(name);
	if (js == 0) {
		jsService->insertProc(this);
	} else {
		js->insertProc(this);
	}
}

////////////////////////////////////////////////////////////////////////////////

MprEjsProc::~MprEjsProc()
{
	//	Will automatically get deleted when the scriptEngine is removed
	
#if OLD
	if (scriptEngine) {
		scriptEngine->removeProc(name);
	}
#endif
	mprFree(name);
}

////////////////////////////////////////////////////////////////////////////////

MprScriptEngine *MprEjsProc::getScriptEngine()
{
	return (MprScriptEngine*) scriptEngine;
}

////////////////////////////////////////////////////////////////////////////////

void MprEjsProc::setScriptEngine(MprEjs *js)
{
	scriptEngine = js;
}

////////////////////////////////////////////////////////////////////////////////
#else
void mprMprEjsServiceDummy() {}

#endif // BLD_FEATURE_EJS_MODULE 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
