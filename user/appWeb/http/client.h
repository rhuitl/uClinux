///
///	@file 	client.h
/// @brief 	HTTP client header
///
///	The Client module provides client-side support for the HTTP protocol.
///
///	This modules is thread-safe.
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
#ifndef _h_CLIENT
#define _h_CLIENT 1

#include	"mpr.h"
#include	"shared.h"

/////////////////////////////////// Defines ////////////////////////////////////
//
//	Constants
//
#define MPR_HTTP_CLIENT_NAME	"mbedthis-client/" BLD_VERSION

#if BLD_FEATURE_SQUEEZE
#define MPR_HTTP_CLIENT_BUFSIZE	(512)			// General I/O buffer size
#define MPR_HTTP_MAX_CONTENT	(32 * 1024)		// Max data on client request
#else
#define MPR_HTTP_CLIENT_BUFSIZE	(1024 * 4)		// General I/O buffer size
#define MPR_HTTP_MAX_CONTENT	(64 * 1024)		// Max data on client request
#endif

#define MPR_HTTP_CLIENT_RETRIES	(2)
#define MPR_HTTP_CLIENT_TIMEOUT	(45 * 1000)		// A bit shorter than server 

// 
//	Input states
// 
#define MPR_HTTP_CLIENT_START	0x1			// Starting state 
#define MPR_HTTP_CLIENT_HEADER	0x2			// Ready to read first line 
#define MPR_HTTP_CLIENT_CONTENT	0x4			// Reading posted content
#define MPR_HTTP_CLIENT_DONE	0x10		// Processing complete

// 
//	Client flags
// 
#define MPR_HTTP_KEEP_ALIVE		0x1			// Keep connection alive for more 
#define MPR_HTTP_TERMINATED		0x2			// Request prematurely terminated
#define MPR_HTTP_COMPLETE		0x4			// Request complete

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaClient ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaClient;

typedef void		(*MaClientProc)(MaClient* cp, void *arg);

class MaClient : public MprLink {
  private:
	MprStr			serverAlgorithm;
	MprStr			serverDomain;
	MprStr			serverNonce;
	MprStr			serverOpaque;
	MprStr			serverRealm;
	MprStr			serverQop;
	MprStr			serverStale;
	MprStr			serverAuthType;		// Basic or Digest
	int				authNc;
	MprStr			authCnonce;

	void			*callbackArg;		// Argument to callback 
	int				contentLength;		// Length of content data 
	int				contentRemaining;	// Remaining content data to read
	MaClientProc	callback;			// Response callback structure 
	MprStr			currentHost;		// Kept-alive host
	int				currentPort;		// Kept-alive port
	MprStr			defaultHost;		// Default target host (if unspecified)
	int				defaultPort;		// Default target port (if unspecified)
	MprStr			errorMsg;			// Error message if failure 
	int				fd;					// Underlying socket file handle
	int				flags;				// Control flags 
	MprHashTable	*headerValues;		// Headers keyword values
	MprBuf*			inBuf;				// Response input data
	MprBuf*			outBuf;				// Request output buffer
	MprStr			password;			// As the name says
	MprStr			proxyHost;			// Proxy host to connect via
	int				proxyPort;			// Proxy port to connect via
	MprStr			realm;				// Authorization realm
	int				responseCode;		// Url response code 
	MprStr			responseProto;		// Response protocol
	MprBuf*			responseContent;	// Response data 
	MprBuf*			responseHeader;		// Response header
	MaUrl			url;				// Request url
	MprStr			responseText;		// Request response message 
	int				retries;			// Max number of retry attempts
	MprStr			secret;				// Random bytes to use in authentication
	MprSocket		*sock;				// Underlying socket handle
	int				state;				// Read handler state 
	int				timeoutPeriod;		// Timeout value
	MprTimer		*timer;				// Timeout handle 
	int				timestamp;			// Timeout timestamp for last I/O 
	int				userFlags;			// User flags (same set as flags)
	MprStr			user;				// User account name

#if BLD_FEATURE_MULTITHREAD
	MprCond			*completeCond;		// Signalled when request is complete
	MprMutex		*mutex;				// Mutli-thread sync
#endif

  public:
	MprLogModule	*tMod;				// Logging module

  public:
					MaClient();
					~MaClient();

	int				createSecret();
	int				deleteRequest(char *url);
	void			dispose();
	int				getRequest(char *url);
	int				postRequest(char *url, char *postData, int postLen);
	int				headRequest(char *url);
	int				getFd() { return fd; };
	int				getFlags();
	char			*getHeaderVar(char *key);
	char			*getHost();
	void			getParsedUrl(MaUrl** url);
	int				getPort();
	int				getResponseCode();
	char			*getResponseContent(int *contentLen);
	char			*getResponseHeader();
	char			*getResponseMessage();
	MprSocket		*getSock() { return sock; };
	int				getState();
	int				inUse(int adjustment);
	bool			isDisposed();
	int				optionsRequest(char *url);
	int				readEvent();
	void			resetAuth();
	void			setAuth(char *realm, char *user, char *password);
	void			setHost(char *host);
	void			setPort(int num);
	void			setKeepAlive(bool on);
	void			setProxy(char *host, int port);
	int				sendRequest(char *host, int port, MprBuf *hdrBuf, 
						char *post, int len);
	void			setRetries(int count);
	void			setTimeout(int timeout);
	void			setCallback(MaClientProc fn, void *arg);
	void			signalComplete();
	void			timeout(MprTimer *tp);
	int				traceRequest(char *url);

#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() {};
	inline void		unlock() {};
#endif

  private:
	void			formatError(char *fmt, ...);
	int				parseAuthenticate(char *authDetails);
	int				parseFirst(char *line);
	int				parseHeader(char *line);
	int				processResponseData();
	void			finishRequest(bool closeSocket);
	void			reset();
	int				sendCore(char *op, char *url, char *postData, int postLen);
	int				sendRetry(char *op, char *url, char *postData, int postLen);
};

////////////////////////////////////////////////////////////////////////////////
#endif // _h_CLIENT 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
