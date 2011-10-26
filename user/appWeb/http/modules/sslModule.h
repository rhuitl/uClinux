///
///	@file 	sslModule.h
/// @brief 	Header for the sslHandler
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
#ifndef _h_SSL_MODULE
#define _h_SSL_MODULE 1

#include	"http.h"

/////////////////////////////// Extern Definitions /////////////////////////////
#if BLD_FEATURE_SSL_MODULE

class MaSslSocket;
class MaSslHandler;
class MaSslHandlerService;
class MaSslModule;
class MaSslConfig;

extern "C" {
	extern int mprSslInit(void *handle);
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MaSslModule /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaSslModule : public MaModule {
  private:
	MprLogModule	*log;
	MprHashTable	*sslConfigTable;
  public:
					MaSslModule(void *handle);
					~MaSslModule();
	int				parseConfig(char *key, char *value, MaServer *server, 
						MaHost *host, MaAuth *auth, MaDir* dir, 
						MaLocation *location);
	int				start();
	void			stop();
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// MaSslProvider ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaSslProvider {
  private:
	MprStr			name;
  public:
					MaSslProvider(char *name);
	virtual			~MaSslProvider();
	virtual MaSslConfig		
					*newConfig(MaHost *host);
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MaSslConfig /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

//
//	SSL protocols
//
#define MPR_HTTP_PROTO_SSLV2	0x1
#define MPR_HTTP_PROTO_SSLV3	0x2
#define MPR_HTTP_PROTO_TLSV1	0x4
#define MPR_HTTP_PROTO_ALL		0x7

//
//	Per host SSL configuration information
//
class MaSslConfig : public MprHashEntry {
  public:
	MaHost			*host;
	MprStr			keyFile;
	MprStr			certFile;
	MprStr			caFile;
	MprStr			caPath;
	MprStr			ciphers;
	int				verifyClient;
	int				verifyDepth;
	int				protocols;

  public:
					MaSslConfig(MaHost *host);
					~MaSslConfig();
	virtual MprSocket *newSocket();
	void			setKeyFile(char *path);
	void			setCertFile(char *path);
	void			setCaFile(char *path);
	void			setCaPath(char *path);
	void			setCipherSuite(char *ciphers);
	void			setVerifyClient(bool verifyClient);
	void			setVerifyDepth(int depth);
	void			setSslProto(int mask);
	virtual int		start();
	virtual void	stop();
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaSslSocket //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaSslSocket : public MprSocket {
  private:
	bool			initialized;

  protected:
	bool			connTraced;
	MaSslConfig		*config;

  public:
					MaSslSocket(MaSslConfig *config);
	bool			dispose();
	bool			getEof();
	MaSslConfig		*getConfig();
	void 			ioProc(int mask, int isPoolThread);

	virtual			~MaSslSocket();
	virtual int		initConnection();
	virtual MprSocket 
					*newSocket();
	virtual int		read(char *buf, int bufsize);
	virtual int		write(char *buf, int bufsize);

	//
	//	Providers must invoke the base method for these virtual methods 
	//
	virtual void	close(int how);
	virtual int		flush();
};

////////////////////////////////////////////////////////////////////////////////
#else

void mprSslDummy();
#endif // BLD_FEATURE_SSL_MODULE
#endif // _h_SSL_MODULE 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
