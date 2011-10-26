//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//
///	@file 	php4Handler.h
/// @brief 	Header for the phpHandler
///
////////////////////////////////// Includes ////////////////////////////////////

#ifndef _h_PHP4_MODULE
#define _h_PHP4_MODULE 1

//
//	Must always use Zend Thread Safety (appWeb is multi-threaded)
#define ZTS 1

//
//	PHP includes crtdbg.h which messes up _delete definitions
//
#define _INC_CRTDBG

//
//	For PHP5
//
#define PTHREADS 1

#ifndef UNSAFE_FUNCTIONS_OK
#define UNSAFE_FUNCTIONS_OK 1
#endif

#include	"http.h"

#if BLD_FEATURE_PHP4_MODULE

#if WIN
#define PHP_WIN32
#define ZEND_WIN32
#endif

#include	<math.h>

//
//	Windows binary build does not define this
//
#ifndef ZEND_DEBUG
#define ZEND_DEBUG 0
#endif

#if PHP5
#define MA_PHP_MODULE_NAME	"php5"
#define MA_PHP_HANDLER_NAME	"php5Handler"
#define MA_PHP_LOG_NAME		"php5"
#else
#define MA_PHP_MODULE_NAME	"php4"
#define MA_PHP_HANDLER_NAME	"php4Handler"
#define MA_PHP_LOG_NAME		"php4"
#endif

extern "C" {

#if BLD_FEATURE_DLL == 0
//
//	Need this to prevent crtdbg.h defining "delete()" when linking statically
//
#define _MFC_OVERRIDES_NEW
#endif

#include <main/php.h>
#include <main/php_globals.h>
#include <main/php_variables.h>
#include <Zend/zend_modules.h>
#include <main/SAPI.h>

#ifdef PHP_WIN32
	#include <win32/time.h>
	#include <win32/signal.h>
	#include <process.h>
#else
	#include <main/build-defs.h>
#endif

#include <Zend/zend.h>
#include <Zend/zend_extensions.h>
#include <main/php_ini.h>
#include <main/php_globals.h>
#include <main/php_main.h>
#include <ext/standard/info.h>
#include <TSRM/TSRM.h>
}

/////////////////////////////// Forward Definitions ////////////////////////////

class MaPhp4Handler;
class MaPhp4HandlerService;
class MaPhp4Module;

extern "C" {
#if PHP5
	extern int mprPhp5Init(void *handle);
#else
	extern int mprPhp4Init(void *handle);
#endif
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaPhp4Module /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaPhp4Module : public MaModule {
  private:
	MaPhp4HandlerService 
					*phpHandlerService;
  public:
					MaPhp4Module(void *handle);
					~MaPhp4Module();
	void			unload();
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaPhp4Handler ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaPhp4HandlerService : public MaHandlerService {
  private:
	MprLogModule	*log;					// Mpr log handle

  public:
					MaPhp4HandlerService();
					~MaPhp4HandlerService();
	MaHandler		*newHandler(MaServer *server, MaHost *host, char *ex);
	int				start();
	int				stop();
};


class MaPhp4Handler : public MaHandler {
  public:
	int 			phpInitialized;			// Can execute
	void 			*func_data;				// function data
	zval 			*var_array;				// Track var array
	MprLogModule	*log;					// Pointer to Php4HandlerServer log

  public:
					MaPhp4Handler(MprLogModule *serviceLog, char *extensions);
					~MaPhp4Handler();
	MaHandler		*cloneHandler();
	int				run(MaRequest *rq);
	int				execScript(MaRequest *rq);
};

////////////////////////////////////////////////////////////////////////////////
#endif // BLD_FEATURE_PHP4_MODULE
#endif // _h_PHP4_MODULE 
