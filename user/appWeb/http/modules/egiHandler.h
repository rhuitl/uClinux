///
///	@file 	egiHandler.h
/// @brief 	Header for the egiHandler
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
#ifndef _h_EGI_MODULE
#define _h_EGI_MODULE 1

#include	"http.h"

/////////////////////////////// Forward Definitions ////////////////////////////

class MaEgiForm;
class MaEgiHandler;
class MaEgiHandlerService;

extern "C" {
	extern int mprEgiInit(void *handle);
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MaEgiModule ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaEgiModule : public MaModule {
  private:
  public:
					MaEgiModule(void *handle);
					~MaEgiModule();
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// MaEgiForm /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

///
///	@brief Create an EGI form
///
///	EGI forms are created via the MaEgiForm class. Instances are created 
///	for each EGI form. When a HTTP request is serviced that specifies the
///	EGI form, the run method will be invoked. The run method should return
///	to the browser the appropriate data.
///
class MaEgiForm : public MprHashEntry {
  private:
	char			*name;
  public:
	///
	///	@synopsis Constructor to create an EGI form
	///	@overview Instances of this class represent EGI forms. When an EGI
	///		form is invoked, the run method is called. For example:
	///		the URL: 
	///
	///	@code
	///		http://localhost/egi/myForm?name=Julie
	///	@endcode
	///
	///	could be enabled by calling maDefineEgiForm("myForm", myFormProc);	
	///	@param formName Name to publish the form as. This appears in the URL. 
	///		Names must therefore only contain valid URL characters.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see MaEgiForm
					MaEgiForm(char *formName);
					MaEgiForm(MaServer *server, MaHost *host, char *formName);
	virtual			~MaEgiForm();
	char			*getName();
	virtual void	run(MaRequest *rq, char *script, char *path, 
						char *query, char *postData, int postLen);
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////// MaEgiHandlerService //////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaEgiHandlerService : public MaHandlerService {
  private:
	MprHashTable	*forms;					// Table of functions 
	MprList			handlerHeaders;			// List of handler headers
	MprLogModule	*log;

#if BLD_FEATURE_MULTITHREAD
	MprMutex		*mutex;
#endif

  public:
					MaEgiHandlerService();
					~MaEgiHandlerService();
	void			insertForm(MaServer *server, MaHost *host, 
						MaEgiForm *form);
	MaHandler		*newHandler(MaServer *server, MaHost *host, char *ex);

#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() { };
	inline void		unlock() { };
#endif
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// EgiHandler //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	A master instance of the EgiHandler is create for each referencing host.
//	A request instance is cloned from this for each request.
//

//
//	egiFlags
//
#define MPR_EGI_NON_PARSED_HEADER	0x1		// CGI program creates HTTP headers
#define MPR_EGI_HEADER_SEEN			0x2		// Server has parsed CGI response
#define MPR_EGI_CLONED				0x4		// Cloned handler

class MaEgiHandler : public MaHandler {
  private:
	int				egiFlags;
	MprHashTable	*forms;					// Pointer to service forms
	MprLogModule	*log;					// Pointer to the service log
	MprBuf*			postBuf;

  public:
					MaEgiHandler(char *ext, MprLogModule *log, 
					MprHashTable *forms);
					~MaEgiHandler();
	MaHandler		*cloneHandler();
	char			*getHostName();
	void			insertForm(MaEgiForm *form);
	void			postData(MaRequest *rq, char *buf, int buflen);
	int				run(MaRequest *rq);
	int				setup(MaRequest *rq);
};

////////////////////////////////////////////////////////////////////////////////
#endif // _h_EGI_MODULE 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
