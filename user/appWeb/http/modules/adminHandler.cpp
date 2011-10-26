///
///	@file 	adminHandler.cpp
/// @brief 	Admin handler for run-time diagnostics
///
///	Starting framework for a admin handler. Currently supports /admin/exit
///	to request that the server terminate.
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

#include	"adminHandler.h"

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaAdminModule ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_ADMIN_MODULE

int mprAdminInit(void *handle)
{
	if (maGetHttp() == 0) {
		return MPR_ERR_NOT_INITIALIZED;
	}
	new MaAdminModule(handle);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MaAdminModule::MaAdminModule(void *handle) : MaModule("admin", handle)
{
	adminHandlerService = new MaAdminHandlerService();
}

////////////////////////////////////////////////////////////////////////////////

MaAdminModule::~MaAdminModule()
{
	delete adminHandlerService;
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// MaAdminHandlerService /////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaAdminHandlerService::MaAdminHandlerService() : 
	MaHandlerService("adminHandler")
{
}

////////////////////////////////////////////////////////////////////////////////

MaAdminHandlerService::~MaAdminHandlerService()
{
}

////////////////////////////////////////////////////////////////////////////////

MaHandler *MaAdminHandlerService::newHandler(MaServer *server, MaHost *host, 
	char *ext)
{
	return new MaAdminHandler();
}

//////////////////////////////////// Code //////////////////////////////////////

MaAdminHandler::MaAdminHandler() : 
	MaHandler("adminHandler", 0, 
		MPR_HANDLER_ALL | MPR_HANDLER_MAP_VIRTUAL | MPR_HANDLER_TERMINAL)
{
}

////////////////////////////////////////////////////////////////////////////////

MaAdminHandler::~MaAdminHandler()
{
}

////////////////////////////////////////////////////////////////////////////////

MaHandler *MaAdminHandler::cloneHandler()
{
	return new MaAdminHandler();
}

////////////////////////////////////////////////////////////////////////////////

int MaAdminHandler::run(MaRequest *rq)
{
	char			*uri;

	uri = rq->getUri();
	rq->setResponseCode(200);
#if BLD_FEATURE_KEEP_ALIVE
	rq->setNoKeepAlive();
#endif

	rq->writeFmt("HTTP/1.0 200 OK\r\nServer: %s\r\n", MPR_HTTP_SERVER_NAME);
	rq->writeFmt("Content-type: text/plain\r\n");
	rq->write("Connection: close\r\n");
	rq->write("\r\n");

	//	FUTURE -- convert this to output HTML to the browser
	//	FUTURE -- should be able to hook MemStats output and send to browser
	if (strcmp(uri, "/admin/memUsage") == 0) {
		mprPrintMemStats();
#if LINUX || MACOSX
		mprPrintf("Brk %x, %,d\n", sbrk(0), sbrk(0));
#endif

	} else if (strcmp(uri, "/admin/exit") == 0) {
		rq->flushOutput(MPR_HTTP_FOREGROUND_FLUSH, MPR_HTTP_FINISH_REQUEST);
		mprGetMpr()->terminate();
		return MPR_HTTP_HANDLER_FINISHED_PROCESSING;

	} else if (strcmp(uri, "/admin/httpStats") == 0) {
		mprPrintf("\nHTTP Statistics\n");
		mprPrintf("---------------\n");
		mprPrintf("accessErrors      %,14d\n", rq->host->stats.accessErrors);
		mprPrintf("activeRequests    %,14d\n", rq->host->stats.activeRequests);
		mprPrintf("maxActiveRequests %,14d\n", 
			rq->host->stats.maxActiveRequests);
		mprPrintf("errors            %,14d\n", rq->host->stats.errors);
		mprPrintf("keptAlive         %,14Ld\n", rq->host->stats.keptAlive);
		mprPrintf("requests          %,14Ld\n", rq->host->stats.requests);
		mprPrintf("redirects         %,14d\n", rq->host->stats.redirects);
		mprPrintf("timeouts          %,14d\n", rq->host->stats.timeouts);
		mprPrintf("copyDowns         %,14d\n\n", rq->host->stats.copyDown);

#if BLD_DEBUG && BLD_FEATURE_MULTITHREAD
	} else if (strcmp(uri, "/admin/poolStats") == 0) {
		MprPoolStats	poolStats;
		mprGetMpr()->poolService->getStats(&poolStats);
		mprPrintf("\nPool Statistics\n");
		mprPrintf("---------------\n");
		mprPrintf("timeouts    %,8d\n\n", rq->host->stats.timeouts);
		mprPrintf("maxThreads  %,8d\n", poolStats.maxThreads);
		mprPrintf("minThreads  %,8d\n", poolStats.minThreads);
		mprPrintf("numThreads  %,8d\n", poolStats.numThreads);
		mprPrintf("maxUse      %,8d\n", poolStats.maxUse);
		mprPrintf("idleThreads %,8d\n", poolStats.idleThreads);
		mprPrintf("busyThreads %,8d\n\n", poolStats.busyThreads);
#endif
	} else {
		rq->requestError(404, "Unsupported administration command");
		return MPR_HTTP_HANDLER_FINISHED_PROCESSING;
    }
	rq->flushOutput(MPR_HTTP_FOREGROUND_FLUSH, MPR_HTTP_FINISH_REQUEST);
	return MPR_HTTP_HANDLER_FINISHED_PROCESSING;
}

////////////////////////////////////////////////////////////////////////////////
#else
void mprAdminHandlerDummy() {}

#endif // BLD_FEATURE_ADMIN_MODULE

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
