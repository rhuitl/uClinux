///
///	@file 	http.h
/// @brief 	Primary header for the Mbedthis Http Web Server
///
///	The Str type implies that the string has been dynamically allocated.
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
#ifndef _h_HTTP
#define _h_HTTP 1

#include	"mpr.h"
#include	"shared.h"

/////////////////////////////// Forward Declarations ///////////////////////////

class	MaAlias;
class	MaAliasService;
class	MaAuth;
class	MaApplet;
class	MaDataStream;
class	MaHandler;
class	MaHandlerService;
class	MaHeader;
class	MaHost;
class	MaHostAddress;
class	MaHttp;
class	MaHttpError;
class	MaHttpMime;
class	MaListen;
class	MaLocation;
class	MaMimeHashEntry;
class	MaModule;
class	MaRequest;
#if BLD_FEATURE_ROMFS
class	MaRomFileSystem;
class	MaRomInode;
class	MaRomFile;
class	MaRomHashEntry;
#endif
class	MaServer;
#if BLD_FEATURE_SESSION
class	MaSession;
#endif
class	MaVhost;
class	MaDir;
class	MaStats;

//
//	Special import for SslConfig
//
class	MaSslConfig;

/////////////////////////////////// Defines ////////////////////////////////////

#if BLD_FEATURE_SQUEEZE
#define MPR_HTTP_BUFSIZE			(512)
#define MPR_HTTP_DOC_BUFSIZE		(512)
#define MPR_HTTP_IN_BUFSIZE			(512)
#else
#define MPR_HTTP_BUFSIZE			(2048)
#define MPR_HTTP_DOC_BUFSIZE		(1024)
#define MPR_HTTP_IN_BUFSIZE			(4096)
#endif

#define MPR_HTTP_SERVER_NAME		"Mbedthis-AppWeb/" BLD_VERSION
#define MPR_HTTP_SERVER_TIMEOUT		(300 * 1000)	// Overridden in http.conf
#define MPR_HTTP_SESSION_TIMEOUT	(1800)			// 30 mins "  "  "

//
//	Service name and display name of the service
//	FUTURE -- move into winAppWeb and winHttp.
//
#define MPR_HTTP_SERVICE_NAME		"Mbedthis-AppWeb"
#define MPR_HTTP_SERVICE_DISPLAY 	"Mbedthis AppWeb HTTP Server"

// 
//	Primary state machine states for the web server
// 
#define MPR_HTTP_START			0x1			// Starting state 
#define MPR_HTTP_HEADER			0x2			// Ready to read first line 
#define MPR_HTTP_RUN_HANDLERS	0x4			// Start running handlers
#define MPR_HTTP_RUNNING		0x8			// Processing request
#define MPR_HTTP_DONE			0x10		// Processing complete

// 
//	Server and Client flags
//
#define MPR_HTTP_KEEP_ALIVE		0x1			// Keep connection alive after req
#define MPR_HTTP_COOKIE			0x2			// Cookie supplied
#define MPR_HTTP_IF_MODIFIED	0x4			// If-modified-since supplied
#define MPR_HTTP_POST_REQUEST	0x8			// Post method
#define MPR_HTTP_LOCAL			0x10		// Request originate on local system
#define MPR_HTTP_SOCKET_EVENT	0x20		// Request came through socketEvent
#define MPR_HTTP_LENGTH			0x80		// Request specified content length 
#define MPR_HTTP_CONTENT_DATA	0x100		// Has content data
#define MPR_HTTP_CONN_CLOSED	0x200		// Connection closed
#define MPR_HTTP_INCOMPLETE		0x400		// Request prematurely terminated
#define MPR_HTTP_BLOCKING		0x800		// Block waiting for data
#define MPR_HTTP_REUSE			0x1000		// Connection used keep-alive
#define MPR_HTTP_DONT_CACHE		0x4000		// Add no-cache to the response
#define MPR_HTTP_HEADER_WRITTEN	0x8000		// Headers have been output
#define MPR_HTTP_CREATE_ENV		0x10000		// Must create env for this request
#define MPR_HTTP_NO_LENGTH		0x20000		// Dont output a content length
#define MPR_HTTP_OPENED_DOC		0x40000		// Document has been opened
#define MPR_HTTP_CUSTOM_HEADERS	0x80000		// Handler is using custom headers
#define MPR_HTTP_DELETE_REQUEST	0x100000	// DELETE method 
#define MPR_HTTP_GET_REQUEST	0x200000	// HEAD method 
#define MPR_HTTP_HEAD_REQUEST	0x400000	// HEAD method 
#define MPR_HTTP_OPTIONS_REQUEST 0x800000	// OPTIONS method 
#define MPR_HTTP_PUT_REQUEST	0x1000000	// PUT method 
#define MPR_HTTP_TRACE_REQUEST	0x2000000	// TRACE method 
#define MPR_HTTP_PULL_POST		0x4000000	// Pull post data (server only)
#define MPR_HTTP_DONT_AUTO_FINISH 0x8000000	// Don't auto finish the request

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaLimits ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaLimits { 
  public:
	int				maxBody;		//	Max size of an incoming request
	int				maxResponseBody;//	Max size of generated response content
	int				maxFirstLine;	//	Max size of the first request line
	int				maxUrl;			//	Max size of a URL
	int				maxHeader;		//	Max size of the total header
	int				maxNumHeader;	//	Max number of lines of header
	int				maxThreads;		//	Max number of pool threads
	int				minThreads;		//	Min number of pool threads
	int				sendBufferSize;	//	TCP/IP send buffer size
	int				threadStackSize;//	Stack size for each pool thread
  public:
					MaLimits();
					~MaLimits();
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// MaHttp ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

///
///	@brief Top level Http application class.
///
///	There is one instance of the Http class per application. It holds a list
///	of HTTP servers running inside the application.
///

class MaHttp {
  private:
	MprList			handlerServices;		// List of loaded handler services
	MaLimits		limits;
	int				gid;
	char			*group;
	MprList			servers;				// List of web servers
	int				uid;
	char			*user;
	MprList			modules;

#if BLD_FEATURE_MULTITHREAD
	MprMutex		*mutex;					// Multi-thread sync
#endif

  public:
	///
	///	@synopsis Constructor to create the MaHttp object
	///	@overview A MaHttp object is required to use most of the AppWeb 
	///		services. It contains a list of the servers and provides control
	///		over the applictions use of the HTTP service.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see MaHttp, MaServer, Mpr
					MaHttp();
					~MaHttp();				///< Destructor
	int				changeGroup();
	int				changeUser();
	MaModule		*findModule(char *name);
	MaServer		*findServer(char *name);
	char			*getGroup();
	MaLimits		*getLimits() { 
						return &limits; 
					};
	int				getHandlerServicesCount() { 
						return handlerServices.getNumItems(); 
					};
	MprList			*getModules() { return &modules; };				
	char			*getUser();
	void			insertHandlerService(MaHandlerService *hs);
	void			insertModule(MaModule *mp);
	void			insertServer(MaServer *sp);
	MaHandlerService* 
					lookupHandlerService(char *name);
	void			removeHandlerService(MaHandlerService *hs);
	void			removeModule(MaModule *mp);
	int				setGroup(char *s);
	int				setUser(char *s);

	///
	///	@synopsis Activate HTTP servers.
	///	@synopsis Start all the logical servers corresponding to the supplied 
	///		MaHttp object. Once stared, the default server an any virtual 
	///		servers will be activated and begin responding to HTTP requests.
	///	@returns Zero if successful, otherwise a MPR error code is returned.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see stop
	int				start();
	void			startHandlers();
	void			startModules();

	///
	///	@synopsis Deactivate HTTP servers
	///	@overview Stop all the logical servers corresponding to the supplied
	///		MaHttp object. The servers will cease serving new requests 
	///		immediately. Existing requests will continue to be processed 
	///		by the handlers. 
	/// @stability Evolving.
	/// @library libappWeb
	///	@see start
	int				stop();
	void			stopHandlers();
	void			stopModules();

	void			loadStaticModules();
	void			unloadModules();

#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() {};
	inline void		unlock() {};
#endif
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaListen ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaListen : public MprLink {
  private:
	char			*ipAddr;
	int				port;
	MprSocket		*sock;
#if BLD_FEATURE_SSL_MODULE
	bool			secure;
	MaSslConfig	*sslConfig;
#endif

  public:
					MaListen(char *ipAddr, int port);
					~MaListen();
	int				close();
	char			*getIpAddr() { return ipAddr; };
	int				getPort() { return port; };
	int				open(MaServer *sp);
#if BLD_FEATURE_SSL_MODULE
	bool			isSecure() { return secure; };
	void			setSslConfig(MaSslConfig *config);
#endif
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MaHandlerService ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaHandlerService : public MprLink {
  private:
	MprStr			handlerName;

  public:
					MaHandlerService(const char *name);
	virtual			~MaHandlerService();
	char			*getName() { return handlerName; };
	virtual	MaHandler 
					*newHandler(MaServer *server, MaHost *host, char *ex);
	virtual int		start();
	virtual int		stop();
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaHostAddress ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Flags
//
#define MPR_HTTP_IPADDR_VHOST	0x1

class MaHostAddress : public MprHashEntry {
  private:
	MprStr			ipAddr;
	int				port;
	int				flags;
	MprList			vhosts;					// Vhosts using this address
  public:
					MaHostAddress(char *ipAddrPort);
					~MaHostAddress();
	MaHost			*findHost(char *hostStr);
	char			*getIpAddr();
	int				getPort();
	void			insertVhost(MaVhost *vhost);
	bool			isNamedVhost();
	void			setNamedVhost();

	friend class	MaServer;
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaModule ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#define	MPR_MODULE_DLL			0x1			// Module is a DLL vs static link
#define	MPR_MODULE_LOADED		0x2			// Loaded 

class MaModule : public MprLink {
  public:
	int				flags;
	void			*handle;				// If a DLL
	char			*name;

#if BLD_FEATURE_MULTITHREAD
	MprMutex			*mutex;					// Multi-thread sync
#endif

  public:
					MaModule(char *name, void *handle);
	virtual			~MaModule();
	char			*getName();
	void			*getHandle();
	void			setHandle(void *handle);

	virtual int		parseConfig(char *key, char *value, MaServer *server, 
						MaHost *host, MaAuth *auth, MaDir* dir, 
						MaLocation *location);
	virtual int		start();
	virtual void	stop();
	virtual void	unload();

  private:
#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() {};
	inline void		unlock() {};
#endif
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// MaVhost ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaVhost : public MprLink {
  private:
	MaHost		*host;

  public:
					MaVhost(MaHost *host);
					~MaVhost();
	MaHost			*getHost();
	friend class	MaHostAddress;
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaServer ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

///
///	@brief HTTP server possibly listening on multiple ports.
///
///	An application may have any number of HTTP servers, each managed
///	by an instance of the Server class. Typically there will be only one 
///	server in an application. There may be multiple virtual hosts and one 
///	default host for each server class. A server will typically be configured 
///	by calling the configure method for each server which parses a file to 
///	define the server and virtual host configuration.
///

class MaServer : public MprLink {
  public:
	MaHttp			*http;		
	MprLogModule	*tMod;
	MprFileSystem	*fileSystem;
	static MaServer	*MaServer::defaultServer;

  private:
	MprFileSystem	*defaultFileSystem;
	MprList			hosts;					// List of host objects
	MaHost			*defaultHost;			// Primary host
	MprHashTable	*hostAddresses;			// List of HostAddress objects
	int				lineNumber;				// Line in http.conf
	MprList			listens;				// List of listening sockets
	MprStr			name;					// Unique name for this server
	MprStr			serverRoot;
	bool			alreadyLogging;			// Already logging

  public:
	///
	///	@synopsis Constructor to create a HTTP server.
	///	@overview Creates a logical HTTP server that may consist of multiple 
	///		virtual servers. 
	///	@param http Pointer to the MaHttp object created by maCreateHttp.
	///	@param name Descriptive name to give to the server.
	///	@param serverRoot Top level path of the directory containing the server.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see ~MaServer, configure
					MaServer(MaHttp* http, char *name, char *serverRoot);

	///	Destructor.
					~MaServer();

	///
	///	@synopsis configure the entire server from a configuration file.
	///	@overview Servers are configured via an Apache-style configuration file.
	///		A server may listen on multiple ports and may contain multiple 
	///		virtual hosts.
	///	@param configFile Path of the configuration file.
	///	@param outputConfig If TRUE, output the parsed configuration settings
	///		to the standard output (console).
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	int				configure(char *configFile, bool outputConfig);

	int				createHostAddresses(MaHost *host, char *value);
	void			displayConfig();
	static MaServer	*getDefaultServer();
	MaHost			*getDefaultHost();
	MaHost			*findHost(char *name);
	MprFileSystem	*getFileSystem() { return fileSystem; };
	int				getValue(char **value, char *buf, char **nextToken, 
						int quotes);
	MprHashTable	*getHostAddresses();
	///
	///	@synopsis Return the current configuration file line number 
	///	@overview If a error is encountered when parsing the configuration file,
	///		getLine will return the current line number for error
	///		reporting purposes.
	///	@returns The current line number (origin 1).
	/// @stability Evolving.
	/// @library libappWeb
	///	@see configure
	int				getLine() { return lineNumber; };
	MprList			*getListens() { return &listens; };
	char			*getName();
	char			*getServerRoot();
#if BLD_FEATURE_SSL_MODULE
	MaSslConfig		*getSslConfig();
#endif
	int				processSetting(char *key, char *val, MaHost *host, 
						MaDir* dir, MaLocation *location);
	static void		setDefaultServer(MaServer *server);
	void			setFileSystem(MprFileSystem *fs);
	void			setServerRoot(char *path);
	int				splitValue(char **s1, char **s2, char *buf, int quotes);

	///
	///	@synopsis Start the server.
	///	@overview Call to start all hosts within the server.
	///	@return Returns zero if successful, otherwise return a negative MPR
	///		error code.
	int				start();

	///
	///	@synopsis Stop the server.
	///	@overview Call to stop all hosts within the server.
	///	@return Returns zero if successful, otherwise return a negative MPR
	///		error code.
	int				stop();

#if BLD_FEATURE_SSL_MODULE
	int				setSslListeners(MaHost *host, MaSslConfig *config);
#endif
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// MaAuth ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//	Flags
//
#define MPR_HTTP_AUTH_USER_HASH		0x1		// User hash created
#define MPR_HTTP_AUTH_GROUP_HASH	0x2		// Group hash created
#define MPR_HTTP_AUTH_REQUIRED		0x4		// Dir/Location requires auth

enum MaAuthOrder {
	MPR_HTTP_ALLOW_DENY,
	MPR_HTTP_DENY_ALLOW
};

enum MaAuthType {
	MPR_HTTP_AUTH_UNKNOWN,
	MPR_HTTP_AUTH_BASIC,
	MPR_HTTP_AUTH_DIGEST
};

typedef long MaAcl;							// Access control mask

class MaUser : public MprHashEntry {
  private:
	bool			enabled;
	MprStr			password;
	MprStr			realm;
	MprStr			userName;
	MprStr			userRealmKey;
  public:
					MaUser(char *user, char *realm, char *password, bool enabled);
					~MaUser();
	bool			getEnabled() { return enabled; };
	char			*getKey() { return userRealmKey; };
	char			*getName() { return userName; };
	char			*getRealm() { return realm; };
	char			*getPassword() { return password; };
	void			setEnabled(bool e) { enabled = e; };
};

class MaGroup : public MprHashEntry {
  private:
	MaAcl			acl;
	bool			enabled;
	MprStr			groupName;
	MprStringList	*userList;							// List of users
  public:
					MaGroup(char *group, MaAcl acl, bool enabled);
					~MaGroup();
	int				addUser(char *user);
	MaAcl			getAcl() { return acl; };
	bool			getEnabled() { return enabled; };
	char			*getName() { return groupName; };
	MprStringList	*getUsers() { return userList; };
	int				removeUser(char *user);
	void			setAcl(MaAcl acl) { this->acl = acl; };
	void			setEnabled(bool e) { enabled = e; };
};

///
///	@brief Authorization Class
///
///	The MaAuth class is the foundation authorization class and is used as
///	base class by MaDirectory and MaLocation. It stores the authorization
/// configuration information required to determine if a client request
///	should be permitted to the resource controlled by this object. 

class MaAuth : public MprLink {
  private:
	MprStr			allowSpec;
	bool			anyValidUser;
	MaAuthType		authType;
	MprStr			denySpec;
	int				flags;
	MaAuthOrder		order;
	MprStr			qop;
	MprStr			requiredRealm;
	MprStr			requiredGroups;
	MprStr			requiredUsers;

	MprHashTable	*userHash;
	MprHashTable	*groupHash;

  public:
					MaAuth();
					~MaAuth();
	MaAuth			*getAuth() { return this; }
	int				getPassword(char *passBuf, int passLen, char *user, 
						char *realm);
	char			*getAllowSpec();
	bool			getAnyValidUser();
	char			*getDenySpec();
	MprHashTable	*getGroupHash() { return groupHash; };
	char			*getQop();
	char			*getRealm();
	char			*getRequiredGroups();
	char			*getRequiredUsers();
	MaAuthOrder		getOrder();
	MaAuthType		getType();
	MprHashTable	*getUserHash() { return userHash; };
	void			inherit(MaAuth *auth);
	void			inheritUserGroup(MaAuth *auth);
	bool			isUserValid(char *user, char *realm);
	bool			isAuthRequired();	
	void			release();
	void			setAllowSpec(char *spec);
	void			setAnyValidUser();
	void			setDenySpec(char *spec);
	void			setOrder(MaAuthOrder order);
	void			setQop(char *qop);
	void			setRealm(char *realm);
	void			setRequiredGroups(char *groups);
	void			setRequiredUsers(char *users);
	void			setType(MaAuthType typ);

	//
	//	User API
	//

	///
	///	@synopsis Add an authorization group.
	///	@overview Add an authorization group to the MaAuth object.
	///	@param group Name of the authorization group.
	///	@param acl Access control list mask.
	///	@param enable If TRUE, enable the group.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				addGroup(char *group, MaAcl acl, bool enable);

	///
	///	@synopsis Add users to an authorization group.
	///	@overview Add a list of users to to the specified authorization group.
	///	@param group Name of the authorization group.
	///	@param users List of users. User names are separated by white-space.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				addUsersToGroup(char *group, char *users);

	///
	///	@synopsis Add an authorization user.
	///	@overview Add an authorization user to the MaAuth object. The user + 
	///		realm pair must be unique. Multiple user records with differing 
	///		realms are allowed.
	///	@param user Name of the user to add.
	///	@param realm Name of the authorization realm.
	///	@param passwd Encrypted user password.
	///	@param enable If set to TRUE, the user+realm combination will be 
	///		enabled.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				addUser(char *user, char *realm, char *passwd, bool enable);

	///
	///	@synopsis Disable a group.
	///	@overview Disable an authorization group.
	///	@param group Name of the authorization group.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				disableGroup(char *group);

	///
	///	@synopsis Disable a user.
	///	@overview Disable an authorization user. User + Realm pairs are the
	//		unique key.
	///	@param user Name of the user to add.
	///	@param realm Name of the authorization realm.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				disableUser(char *user, char *realm);

	///
	///	@synopsis Enable a group.
	///	@overview Enable an authorization group.
	///	@param group Name of the authorization group.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				enableGroup(char *group);

	///
	///	@synopsis Enable a user.
	///	@overview Enable an authorization user. User + realm pairs are the 
	///		unique key.
	///	@param user Name of the authorization user.
	///	@param realm Name of the authorization realm.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				enableUser(char *user, char *realm);

	///
	///	@synopsis Get an ACL mask
	///	@overview Get an Access Control List mask for a MaAuth object.
	///	@param group Name of the authorization group.
	///	@return Returns the MaAcl mask.
	///
	MaAcl			getAcl(char *group);

	///
	///	@synopsis Get a list of the groups.
	///	@overview Get a list of the authorization groups defined for this
	///		MaAuth object.
	///	@param list String list object to which the group names will be added. 
	///
	void			getGroups(MprStringList *list);

	///
	///	@synopsis Get a list of the users.
	///	@overview Get a list of the authorization users defined for this
	///		MaAuth object.
	///	@param list String list object to which the users names will be added. 
	///
	void			getUsers(MprStringList *list);

	///
	///	@synopsis Test if a group is enabled 
	///	@overview Return TRUE if the specified group is enabled.
	///	@param group Name of the authorization group.
	///	@return Returns TRUE if the group is enabled, otherwise FALSE.
	///
	bool			isGroupEnabled(char *group);

	///
	///	@synopsis Test if a user is enabled 
	///	@overview Return TRUE if the specified user + realm combination 
	///		is enabled.
	///	@param user Name of the authorization user.
	///	@param realm Name of the authorization realm.
	///	@return Returns TRUE if the user is enabled, otherwise FALSE.
	///
	bool			isUserEnabled(char *user, char *realm);

	///
	///	@synopsis Parse an ACL.
	///	@overview Parse an ACL string into an ACL mask.
	///	@param aclStr Hex digit string representing the ACL mask.
	///	@return Returns the ACL.
	///
	MaAcl			parseAcl(char *aclStr);

	///
	///	@synopsis Remove a group.
	///	@overview Remove a group from the authorization configuration.
	///	@param group Name of the authorization group.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				removeGroup(char *group);

	///
	///	@synopsis Remove a user.
	///	@overview Remove a user from the authorization configuration.
	///	@param user Name of the authorization user.
	///	@param realm Name of the authorization realm.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				removeUser(char *user, char *realm);

	///
	///	@synopsis Remove users from an authorization group.
	///	@overview Remove a set of users from the defined set of user members
	///		of a group.
	///	@param group Name of the authorization group.
	///	@param users List of users. User names are separated by white-space.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				removeUsersFromGroup(char *group, char *users);

	///
	///	@synopsis Reset the authorization object.
	///	@overview Reset the authorization object and discard all user and
	///		group authorization records.
	///
	void			reset();

	///
	///	@synopsis Set the ACL mask.
	///	@overview Set the Access Control List mask for an authorization group.
	///	@param group Name of the authorization group.
	///	@param acl Access control list mask.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	///
	int				setAcl(char *group, MaAcl acl);

};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// MaDir ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaDir : public MaAuth {
  private:
	MprStr			indexName;
	MprStr			path;
	int				pathLen;

  public:
					MaDir();
					MaDir(MaDir *master, MaAuth *auth);
					~MaDir();
	inline MaAuth *getAuth() { return (MaAuth*) this; };
	inline char		*getIndex() { return indexName; };
	inline char		*getPath() { return path; };
	inline int		getPathLen() { return pathLen; };
	void			setIndex(char *index);
	void			setPath(char *path);
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaLocation /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Flags
//
#define MPR_HTTP_SCRIPT_ALIAS	0x1				// Location is a script alias

class MaLocation : public MaAuth {
  private:
	int				flags;
	MprStr			prefix;
	int				prefixLen;
	MprStr			handlerName;

  public:
					MaLocation();
					MaLocation(MaAuth *master);
					~MaLocation();
	inline MaAuth 	*getAuth() { return (MaAuth*) this; };
	inline int		getFlags() { return flags; };
	inline char		*getHandlerName() { return handlerName; };
	inline char		*getPrefix() { return prefix; };
	inline int		getPrefixLen() { return prefixLen; };
	void			setHandler(char *handlerName);
	void			setPrefix(char *prefix);
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// MaStats ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Count of handler hits kept in Handler
//

class MaStats {
  public:
	long			accessErrors;			///< Access violations 
	long			activeRequests;			///< Currently active requests
	long			maxActiveRequests;		///< Currently active requests
	long			errors;					///< General errors 
	int64			keptAlive;				///< Requests service on keep-alive
	int64			requests;				///< Total requests
	long			redirects;				///< Redirections 
	long			timeouts;				///< Request timeouts
	long			copyDown;				///< Times buffer had to copy down
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaAliasService ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaAlias : public MprLink {
  private:
	char			*prefix;
	int				prefixLen;
	char			*aliasName;
	int				redirectCode;
  public:
					MaAlias(char *prefix, char *dirName, int code = 0);
					~MaAlias();
	char			*getName() { return aliasName; };
	char			*getPrefix() { return prefix; };
	int				getPrefixLen() { return prefixLen; };
	friend class	MaAliasService;
};

//
//	Flags for mapToStorage
//
#define MPR_HTTP_REDIRECT	0x1
#define MPR_HTTP_ADD_INDEX	0x2

//
//	Shared among all hosts on a server
//
class MaAliasService {
  private:
	MprList			aliases;
#if BLD_FEATURE_MULTITHREAD
	MprMutex		*mutex;					// Multh-thread sync
#endif
  public:
					MaAliasService();
					~MaAliasService();
	int				insertAlias(MaAlias* ap);
	int				mapToStorage(MaRequest *rq, char *uri, char *path, 
						int len, int flags);

#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() { };
	inline void		unlock() { };
#endif
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MaMimeHashEntry ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Mime Type hash table entry (the URL extension is the key)
//
class MaMimeHashEntry : public MprHashEntry {
  private:
	MprStr			mimeType;
	MprStr			actionProgram;
  public:
					MaMimeHashEntry(char *ext, char *mimeType);
	virtual			~MaMimeHashEntry();
	char			*getMimeType() { return mimeType; };
	void			setActionProgram(char *actionProgram);
	char			*getActionProgram() { return actionProgram; };
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaSession //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_SESSION

///
///	@brief Session data store to store user's state data.
///
///	The MaSession class provides persistent data storage for user's state data
///	accross multiple requests. The MaSession is a subclass of the MprHashEntry
///	class which allows MaSession instances to be stored in a MprHashTable for
///	quick access by their session ID values.
///
class MaSession : public MprHashEntry {
  private:
	MaHost			*host;					// Host containing session
	MprHashTable	*sessionData;			// Actual session data
	MprTimer		*expiryTimer;			// Session timeout timer
	int				timeoutStart;			// Time expiry timer started
	int				lastActivity;			// Time of last session activity
#if BLD_FEATURE_MULTITHREAD
	MprMutex		*mutex;					// Multi-thread sync
#endif

  public:
	///
	///	@synopsis Construct a new session data store.
	///	@overview Sessions are created and associated with a serving host.
	///		The constructor is supplied a unique session ID that will be
	///		used as the key for the hash entry for the Session object. 
	///	@param host Pointer to the host object owning the session.
	///	@param sessionId Pointer to a unique character string session
	///		identifier.
	///	@param timeout Timeout for the session in seconds. If after the timeout
	///		has expired and no session activity has occurred, the sesion will
	///		be disposed.
	///
					MaSession(MaHost *host, char *sessionId, int timeout);
					~MaSession();
	///
	///	@synopsis Get the value of a session data item.
	///	@overview Data is stored in key/value pairs. 
	///	@param key Key value to retrieve.
	///	@return Returns a pointer to the value of the key. Do not free.
	///
	char			*get(char *key);
	///
	///	@synopsis Return the Session ID 
	///	@overview Return the session ID associated with this session. Session
	///		IDs are strings that are unique in the server responding to the
	///		request.
	///	@return Returns a pointer to the Session ID string. Do not free.
	char			*getId() { return getKey(); };
	MaHost			*getHost() { return host; };
	int				getLastActivity() { return lastActivity; };
	int				getTimeoutStart() { return timeoutStart; };
	void			setTimeoutStart(int t) { timeoutStart = t; };

	///
	///	@synopsis Update a session value 
	///	@overview Update the session value for a given key.
	///	@param key The name of the session data item to update.
	///	@param value The value of the session data item.
	void			set(char *key, char *value);
	///
	///	@synopsis Unset a session data item.
	///	@overview Unset and undefine a session data item.
	///	@param key The name of the session data item to update.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	int				unset(char *key);

#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() { };
	inline void		unlock() { };
#endif
};

#endif
////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// MaHost ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Flags
//
#define MPR_HTTP_HOST_REUSE_MIME	0x1		// Reuse another hosts mime types
#define MPR_HTTP_VHOST				0x2		// Is a virtual host
#define MPR_HTTP_NAMED_VHOST		0x4		// Named virtual host

///
///	@brief A single HTTP host listening on one TCP/IP endpoint.
///
///	A Host object represents a single HTTP connection endpoint. This may be
///	a default server or a virtual server. Multiple Hosts may be contained 
///	within a single Server.
///
class MaHost : public MprLink {
  public:
	MaServer		*server;
	MaStats			stats;

	//	FUTURE -- OPT. Convert as many pointers as possible to put data inline
  private:
	MaAliasService*	
					aliasService;
	bool			authEnabled;
	MprList			dirs;					// List of Directory definitions
	MprStr			documentRoot;
	int				flags;
	MprList			handlers;				// List of handlers for this host 
	int				httpVersion;			// HTTP/1.X
	MprStr			ipAddr;					// IP address (with wildcards)
	MaLimits		*limits;				// Pointer to http->limits
	MprList			locations;				// List of Location defintions
	MprHashTable	*mimeTypes;
#if BLD_FEATURE_DLL
	MprStr			moduleDirs;				// Directories for modules
#endif
	MprStr			name;					// ServerName directive
	MprList			requests;
	MprStr			secret;					// Random bytes for authentication
	int				timeout;				// Timeout for requests
	MprLogModule	*tMod;

#if BLD_FEATURE_SESSION
	MprHashTable	*sessions;				// Session tables
	int				sessionTimeout;			// Default session timeout
#endif

#if BLD_FEATURE_ACCESS_LOG
	int				logFd;
	char			*logFormat;
	MaHost			*logHost;				// If set, use this hosts logs
	char			*logPath;
#endif

#if BLD_FEATURE_KEEP_ALIVE
	int				keepAlive;				// Keep alive supported
	int				keepAliveTimeout;		// Timeout for keep-alive
	int				maxKeepAlive;			// Max keep-alive requests
#endif

#if BLD_FEATURE_MULTITHREAD
	MprMutex		*mutex;
#endif

#if BLD_FEATURE_SSL_MODULE
	bool			secure;
#endif

  public:
	///	Constructor
					MaHost(MaServer *sp);
	///	Destructor
					~MaHost();
	void 			addMimeType(char *mimeType, char *ext);
	void			copyHandlers(MaHost *host);
	void			deleteHandlers();
	void			disableAuth() { authEnabled = 0; };
	void			enableAuth() { authEnabled = 1; };
	MaDir			*findDir(char *path);
	MaDir			*findBestDir(char *path);
	MaAliasService	
					*getAliasService() { return aliasService; };
	MprList			*getDirs();
	char			*getDocumentRoot() { return documentRoot; };
	MprList			*getHandlers();
	int				getHttpVersion() { return httpVersion; };
	char			*getIpAddr() { return ipAddr; };
	MprList			*getLocations();
	MaLimits		*getLimits() { return limits; };
#if BLD_FEATURE_ACCESS_LOG
	char			*getLogFormat() { return logFormat; };
	int				getLogFd() { return logFd; };
	MaHost			*getLogHost() { return logHost; };
#endif
	MprHashTable	*getMimeTypes();
	char			*getMimeActionProgram(char *mimeType);
#if BLD_FEATURE_DLL
	char			*getModuleDirs() { return moduleDirs; };
#endif
	char			*getName() { return name; };
	char			*getSecret() { return secret; };
	MaServer		*getServer() { return server; };
	int				getTimeout() { return timeout; };
	int				insertAlias(MaAlias* ap);
	void			insertDir(MaDir* dp);
	int				insertLocation(MaLocation *loc);
	void			insertHandler(MaHandler *hp);
	void			insertRequest(MaRequest *rq);
	bool			isAuthEnabled() { return authEnabled; };
	bool			isVhost();
	bool			isNamedVhost();
	char			*lookupMimeType(char *ext);
	MaHandler		*lookupHandler(char *name);
	char			*makePath(char *buf, int buflen, char *file, 
						bool validate = 1);
	int				mapToStorage(MaRequest *rq, char *uri, char *path, 
							int len, int flags) {
						return aliasService->mapToStorage(rq, uri, path, 
							len, flags);
					};
	MaHandler		*matchHandlers(MaRequest *rq, char *uri);
	int				openMimeTypes(char *path);
	void			removeRequest(MaRequest *rq);
	char			*replaceReferences(char *buf, int buflen, char *str);
	void			setDocumentRoot(char *path);
	void			setHttpVersion(int v) { httpVersion = v; };
	void			setIpAddr(char *ipAddrPort);
	void			setLog(char *path, char *format);
	void			setLogHost(MaHost *host);
	void			setMimeTypes(MprHashTable *table);
	void 			setMimeActionProgram(char *mimeType, char *actionProgram);
	void			setName(char *ipAddrPort);
	void			setModuleDirs(char *path);
	void			setNamedVhost();
	void			setTimeout(int t) { timeout = t; };
	void			setVhost();
	int				start();
	int				stop();
	void			writeLog(char *buf, int len);

#if BLD_FEATURE_KEEP_ALIVE
	int				getKeepAlive() { return keepAlive; };
	int				getKeepAliveTimeout() { return keepAliveTimeout; };
	int				getMaxKeepAlive() { return maxKeepAlive; };
	void			setKeepAlive(int f) { keepAlive = f; };
	void			setKeepAliveTimeout(int t) { keepAliveTimeout = t; };
	void			setMaxKeepAlive(int m) { maxKeepAlive = m; };
#endif
#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() { };
	inline void		unlock() { };
#endif
#if BLD_FEATURE_SESSION
	MaSession		*createSession(int timeout);
	void			destroySession(MaSession *session);
	int				getSessionTimeout() { return sessionTimeout; };
	MprHashTable	*getSessions() { return sessions; };
	MaSession		*lookupSession(char *sessionId);
	void			setSessionTimeout(int t) { sessionTimeout = t; };
#endif

#if BLD_FEATURE_SSL_MODULE
	bool			isSecure() { return secure; };
	void			setSecure(bool on);
#endif
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaDataStream ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

///
///	@brief Output stream for a HTTP request
///
///	Request handlers use DataStreams to buffer and manage the output of data
///	back to the client. Data streams are used for returning static file 
///	content and for dynamically generated data.
///

class MaDataStream : public MprLink {
  public:
	char			*name;
	MprBuf			buf;
	int				size;
	
  public:
					MaDataStream(char *name, int initial, int max);
					~MaDataStream();
	void			flush() { buf.flush(); size = 0; };
	char			*getName() { return name; };
	int				getSize() { return size; };
	void			setSize(int s) { size = s; };
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaHeader ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	The header as received from the client
//

class MaHeader {
  public:
	MprStr			firstLine;

	//
	//	These char *pointers point into various parts of buf
	//
	MprStr			buf;				// Tokenized with '\0'
	char			*method;
	char			*proto;
	char			*uri;

	//
	//	These are set from the headers
	//
	MprStr			authDetails;
	MprStr			authType;
	MprStr			host;
	MprStr			contentMimeType;		// Mime type of the request payload
	MprStr			userAgent;
#if BLD_FEATURE_COOKIE || BLD_FEATURE_SESSION
	MprStr			cookie;
#endif

  public:
					MaHeader();
					~MaHeader();
	void			reset();
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaRequest //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Flags used by finishRequest
//
#define	MPR_HTTP_CLOSE				0x1
#define	MPR_HTTP_DONT_CLOSE			0x0

//
//	Flags used by flushOutput(background, finishRequest)
//
#define	MPR_HTTP_BACKGROUND_FLUSH	0x1
#define	MPR_HTTP_FOREGROUND_FLUSH	0x0
#define MPR_HTTP_FINISH_REQUEST		0x1

//
//	Flags for formatAltResponse
//
#define MPR_HTTP_DONT_ESCAPE		0x1

///
///	@brief Manage a HTTP request from a client
///
///	The Request class manages a HTTP client request to the server. If TCP/IP
///	Keep-Alive is used, the Request object may be reused for subsequent 
///	requests from the client on the same TCP/IP socket connection.
///
class MaRequest : public MprLink {
  public:
	MaHost			*host;				// Pointer to host class
	MaStats			stats;
	MprFileSystem	*fileSystem;		// File system (normal or ROM)

  private:
	MaHostAddress 	*address;
	MprHashTable	*env;
	MprStringList	*responseHeaders;
	int				responseCode;
	int				contentLength;
	char			contentLengthStr[12];

	MprList			outputStreams;
	MaDataStream	*hdrBuf;			// Buffer for headers
	MaDataStream	*docBuf;			// Document to send 
	MaDataStream	*dynBuf;			// Buffer for dynamic (generated) data
	MaDataStream	*writeBuf;			// Just a pointer into the other streams

	int				bytesWritten;
	MaDir*			dir;				// Best matching dir (PTR only)
	MaHandler		*currentHandler;
	MprStr			decodedQuery;
	MprStr			etag;				// Unique identifier tag
	MprStr			extraPath;
	MprFile			*file;				// File to be served
	MprFileInfo		fileInfo;			// File information for the URL
	MprStr			fileName;
	int				flags;
	MprStr			group;				// Supplied via basic / digest auth 
	MprList			handlers;
	MaHeader		header;
	MprBuf*			inBuf;
	int				inUse;				// In use reference count
	uint			lastModified;
	MaLimits		*limits;			// Pointer to http->limits
	MprSocket		*listenSock;
	MaLocation		*location;			// Best matching location (PTR only)
	int				methodFlags;
	MprStr			password;
	char			localPort[8];
	int				remotePort;
	int				remainingContent;	// Remaining content data to read
	int				remainingKeepAlive;
	MprStr			remoteIpAddr;
	char			*requestMimeType;	// Mime type of the URL document
	MprStr			responseMimeType;	// Mime type of the response payload

	MprScriptEngine	*scriptEngine;
	MprStr			scriptName;
	MprSocket		*sock;
	int				socketEventMask;
	int				state;
	MaHandler		*terminalHandler;	// Actual handler doing the processing
	int				timeout;
	MprTimer		*timer;
	int				timestamp;
	MprLogModule	*tMod;
	MprStr			user;				// Supplied via basic / digest auth 
	MprStr			uri;
	MaUrl			url;				// Request url

#if BLD_FEATURE_SESSION
	MaSession		*session;			// Pointer to session object
	MprStr			sessionId;			// Unique session identifier
#endif
#if BLD_FEATURE_MULTITHREAD
	MprMutex		*mutex;
#endif

  public:
					MaRequest(MaHostAddress *ap, MaHost *hp);
					~MaRequest();
	int				acceptEvent(void *data, MprSocket *sock, char *ipaddr, 
						int port, MprSocket *lp, int isPoolThread); 
	void			incAccessError() { stats.accessErrors++; };
	int				backgroundFlush();
	void			cancelOutput();
	void			cancelRequest();
	void			cancelTimeout();
	void			closeSocket();
	void			deleteHandlers();
	void			closeDoc();
	int				compareVar(char *var, char *value);
	void			createEnvironment();
	void			createEnvVars(char *buf, int len);
	void			enableReadEvents(bool on);
	void			enableWriteEvents(bool on);
	void			finishRequest(bool closeSocket = 0);
	void			finishRequest(int code, bool closeSocket);
	int				flushOutput(bool background, bool completeRequired);
	int				foregroundFlush();
	void			formatAltResponse(int code, char *msg, int flags);
	int				getBytesWritten();
	char			*getAuthDetails();
	char			*getAuthType();
	MaAuth			*getAuth();
	int				getContentLength() { return contentLength; }
	MprHashTable	*getEnv() { return env; };
	int				getRemainingContent() { return remainingContent; }
	MaHandler		*getCurrentHandler() { return currentHandler; };
	MaDataStream	*getDocBuf() { return docBuf; };
	MaDataStream	*getDynBuf() { return dynBuf; };
	char			*getEtag() { return etag; };
	char			*getErrorMsg(int code);

	///
	///	@synopsis Return the document file name to satisfy the current HTTP 
	///		request.
	///	@overview Certain URLs are mapped to corresponding documents in the 
	///		file system. These may be HTML pages, CSS files or GIF/JPEG 
	///		graphic files, among other file types. getFileName will return 
	///		the local file system path to the document to return to the user. 
	///		If the URL does not map to a local document, for example: 
	///		EGI requests are served internally and do not map onto
	///		a local file name, then this call will not return meaningful data.
	///	@returns Pointer to the local file name for the document. Returns empty 
	///		string if the handler does not map the URL onto a local document.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see setFileName
	char			*getFileName() { return fileName; };
	MprFileInfo		*getFileInfo() { return &fileInfo; };
	int				getFlags();
	char			*getGroup() { return group; };
	MaHeader		*getHeader() { return &header; };
	char			*getIpAddr() { return listenSock->getIpAddr(); };
	uint			getLastModified() { return lastModified; };
	char			*getMethod() { return header.method; };
	char			*getPassword() { return password; };
	int				getPort() { return listenSock->getPort(); };
	char			*getRequestMimeType() { return requestMimeType; };
	char			*getRequestContentMimeType() { 
						return header.contentMimeType; 
					};
	char			*getOriginalUri();
	char			*getQueryString();
	int				getRemainingKeepAlive() { return remainingKeepAlive; };
	int				getResponseCode() { return responseCode; };
	MprScriptEngine	*getScriptEngine() { return scriptEngine; };
	char			*getScriptName() { return scriptName; };
	MprSocket		*getSocket() { return sock; };
	int				getState() { return state; };
	MaHandler		*getHandler() { return terminalHandler; };
	int				getTimeSinceLastActivity();
	char			*getUri();
	char			*getUser() { return user; };
	char			*getUserAgent() { return header.userAgent; };

	///
	///	@synopsis Return the value of the specified HTTP environment variable
	///	@overview This call will query the value of HTTP environment variables.
	///		These variables are used by CGI, EGI and ESP handlers. ESP pages
	///		and EGI forms may access these variables.
	///	@param var Name of the variable to access.
	///	@param defaultValue Default value to return if the variable is not 
	///		defined.
	///	@returns The value of the variable if it is defined. Otherwise the 
	///		\a defaultValue is returned.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see setVar
	char			*getVar(char *var, char *defaultValue);
	void			insertHandler(MaHandler *hp);
	void			insertDataStream(MaDataStream *dp);
	bool			isDir(char *path);
	void			logRequest();
	int				matchHandlers();
	int				openDoc(char *path);
	void			outputHeader(char *fmt, ...);
	int				parseFirstLine(char *line);
	int				parseHeader(char *line);
	void			processRequest();
	int				readDoc(char *buf, int len);
	int				readEvent();

	///
	///	@synopsis Read post data sent by the client in a HTTP POST request.
	///	@overview This call is used by AppWeb handlers to read post data 
	///		sent by the client. Handlers may operate in PUSH or PULL mode
	///		with respect to post data. In PUSH mode, appWeb will call the
	///		handlers postData method whenever post data arrives. In PULL
	///		mode, the handler calls readPostData when it is ready to accept
	///		post data. To enable PULL mode, a handler should call setPullPost.
	///
	///		readPostData may block while reading POST data. As such it should
	///		only be used when AppWeb is running in multi-threaded mode.
	///	@note In PUSH mode, the postData method will be called when the handler
	///		is idle. It will never be issued on another thread while the 
	///		handler is active.
	///	@param buf Pointer to buffer to store the post data
	///	@param bufsize Length of buf
	///	@returns Returns the number of bytes read. It will return 0 on EOF and
	///		will return a negative MPR error code on errors.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see MaHandler::postData, setPullPost
	///
	int				readPostData(char *buf, int bufsize);

	///
	///	@synopsis Redirect the client to a new location
	///	@overview This call will respond to the current request with a HTTP 
	///		redirection. The redirection may be to another page with
	///		the current web, or it may be to a different server. This request
	///		will set the "Location" HTTP header and the HTTP response code.
	///		The caller must still call flushOutput to send the response and to
	///		close the request.
	///	@param code The HTTP response code to return to the client.
	///	@param url URL representing the new location. May omit the 
	///		"http://server/" prefix for redirections within the exiting web.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see requestError
	void			redirect(int code, char *url);

	///
	///	@synopsis Return an error to the client
	///	@overview If a handler encounters an error, it can call requestError 
	///		to return the appropriate HTTP error code and message to the 
	///		client.
	///	@param code HTTP error code. E.g. 500 for an internal server error.
	///	@param fmt Printf style format string followed by assocated arguments.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see Request, write, redirect
	void			requestError(int code, char *fmt, ...);
	void			reRunHandlers();
	void			reset();
	void			runHandlers();
	void			seekDoc(long offset, int origin);
	void			setBytesWritten(int written);
	void			setDataStream(bool buffered, bool document);
	void			setDir(MaDir *dp) { dir = dp; };
	int				setExtraPath(char *prefix, int prefixLen);

	///
	///	@synopsis Set a HTTP header in the response to the client.
	///	@overview This call will define a header that will be included
	///		in the HTTP response to the client. AppWeb automatically creates
	///		headers such as Server, Date and Content-Length. If 
	///		setHeader is called to define one of these standard headers, 
	///		the defined value will override the AppWeb default. setHeader
	///		can also be used to create custom headers.
	///	@param value Complete header string. This is of the format
	///	@pre Key: Value
	///		Do not include a carriage return or newline in the string. 
	///	@param allowMultiple If omitted or set to FALSE, then each call to
	///		setHeader will replace any previously defined headers. If TRU
	///		setHeader will allow muliple headers for a given key value.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see setResponseCode, setHeaderFlags
	void 			setHeader(char *value, bool allowMultiple = 0);

	///
	///	@synopsis Set various HTTP header response values
	///	@overview This call is a convenience function to alter the standard
	///		HTTP response headers.
	///	@param flags Flags may be set to MPR_HTTP_DONT_CACHE which will cause
	///		AppWeb to emit a "Cache-control: no-cache" header. This instructs
	///		downstream caches, proxies and browsers not to cache the response.
	///		If flags is set to MPR_HTTP_HEADER_WRITTEN, AppWeb will not write
	///		any standard headers and it is assumed that the handler will 
	///		manually construct the HTTP headers in the response. 
	/// @stability Evolving.
	/// @library libappWeb
	///	@see setHeader
	void			setHeaderFlags(int flags);

	///
	///	@synopsis Set the local file name for the document that satisfies 
	///		this request.
	///	@overview This call defines the local file name for a document 
	///		which will be returned to the client.
	///	@param fileName Path name in the local file system for the document.
	///	@returns Returns zero if successful. Otherwise a negative MPR error 
	///		code will be returned. On errors, maSetFileName will call 
	///		requestError and will terminate the request.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see getFileName, getUri, setUri
	int				setFileName(char *fileName);
	void			setFlags(int orFlags, int andFlags);
	void			setGroup(char *group);
	void			setLocation(MaLocation *lp) { location = lp; };
	void			setPassword(char *password);

	///
	///	@synopsis Switch the handler to manually pull the HTTP POST data.
	///	@overview This call is used by handlers to tell AppWeb that post
	///		data must not be sent asynchronously via the postData method.
	///		Instead, the handler desires to read the post data manually.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see getVar
	void			setPullPost();
	void			setResponseCode(int code) { responseCode = code; };
	void			setResponseMimeType(char *mimeType);
	void			setScriptEngine(MprScriptEngine *js);
	void			setState(int s) { state = s; };
	void			setTimeMark();
	void			setUri(char *path);
	void			setUser(char *user);
	int				statDoc(MprFileInfo *info);
	int				setupHandlers();
	int				testVar(char *var);
	int				timeoutCheck();
	int				writeBlk(MaDataStream *dp, char *buf, int len);

	///
	///	@synopsis Write a block of data back to the client.
	///	@overview This call is the most efficient way to return data back to 
	///		the client.
	///	@param buf Pointer to the data buffer to write
	///	@param size Size of the buffer in bytes
	///	@returns Number of bytes written. Should equal \a size. On errors, 
	///		returns a negative MPR error code.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see redirect, requestError, write, writeFmt
	int				write(char *buf, int size);

	///
	///	@synopsis Write a string back to the client.
	///	@overview Write a string back to the client.
	///	@param s Pointer to string to write.
	///	@returns Number of bytes written. On errors, returns a negative MPR 
	///		error code.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see  redirect, requestError, write, writeFmt
	int				write(char *s);

	int				writeEvent(bool completeRequired);

	///
	///	@synopsis Write a formatted string back to the client.
	///	@overview Format a \a printf style string and write back to the client.
	///	@param fmt Printf style format string followed by assocated arguments.
	///	@returns Number of bytes written. On errors, returns a negative MPR 
	///		error code.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see  redirect, requestError, write
	int				writeFmt(char *fmt, ...);

	void			writeHeaders();

	inline int		getFd() { return (sock) ? sock->getFd() : -1; };

	///
	///	@synopsis Set the value of a HTTP environment variable
	///	@overview This call will define the value of an HTTP environment 
	///		variable. These variables are used by CGI, EGI and ESP 
	///		handlers. ESP pages and EGI forms may access these variables. 
	///		The variable will be created if it does not exist. If it 
	///		already exists, its value will be updated.
	///	@param var Name of environment variable to set.
	///	@param value Value to set.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see getVar
	inline void		setVar(char *var, char *value) {
						if (value == 0) {
							value = "";	
						}
						env->insert(new MprStringHashEntry(var, value));
					};

#if BLD_FEATURE_COOKIE || BLD_FEATURE_SESSION
	///
	///	@synopsis Get any cookie sent with this request. 
	///	@overview This call returns the cookie string sent by the client
	///		with the request. 
	///	@returns NULL if no cookie is defined. Otherwise it returns a pointer
	///		to the cookie string. The caller must NOT free this string.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see getCrackedCookie, setCookie
	char			*getCookie();

	///
	///	@synopsis Decode a cookie string and return the cookie components.
	///	@overview This call tokenizes the cookie string sent by the client
	///		with the request and it returns the cookie name, value and path.
	///	@param name Name of the cookie.
	///	@param value Value associated with this name.
	///	@param path URL prefix path for which this cookie applies.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see getCookie, setCookie
	int 			getCrackedCookie(char **name, char **value, char **path);

	///
	///	@synopsis Set a cookie to be defined in the client's browser
	///	@overview This call will define a cookie which will be sent with the
	///		response to the client. Subsequent requests from the browser 
	///		should then contain the cookie. It can be used to create and
	///		track user sessions.
	///	@param name Name of the cookie. Must not contain a leading "$". Must
	///		contain no spaces.
	///	@param value Value of the cookie. Must not contain any spaces.
	///	@param lifetime Time in seconds that the cookie should live.
	///	@param path URL prefix path for which the cookie will be included in
	///		subsequent requests.
	///	@param secure If defined, the cookie is only valid when used with 
	///		SSL connections.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see getCookie, getCrackedCookie
	void 			setCookie(char *name, char *value, int lifetime, 
						char *path, bool secure);
#endif

#if BLD_FEATURE_SESSION
	///
	///	@synopsis Create a new session data store
	///	@overview Create a new session data store and associate it with this
	///		request.
	///	@param timeout Time in seconds for the session data store to live.
	void			createSession(int timeout);

	///
	///	@synopsis Destroy the session data store 
	///	@overview Destroy the session data store associated with this request.
	///		This call will have no effect if a store has not been created.
	void			destroySession();

	///
	///	@synopsis Get the session data store
	///	@overview Get the session data store associated with this request.
	///	@return Returns a pointer to the Session object. Return zero if 
	///		no session data store has been created.
	MaSession		*getSession() { return session; };

	///
	///	@synopsis Get the value of a session data item.
	///	@overview Get the value of the session data item specified by key. If
	///		no item is yet defined, return the defaultValue.
	///	@param key Key value to retrieve.
	///	@param defaultValue The default value to return if the key is not
	///		defined.
	///	@return Returns a pointer to the value of the key. Do not free.
	char			*getSessionData(char *key, char *defaultValue);

	///
	///	@synopsis Return the Session ID 
	///	@overview Return the session ID associated with this session. Session
	///		IDs are strings that are unique in the server responding to the
	///		request.
	///	@return Returns a pointer to the Session ID string. Do not free.
	char			*getSessionId() { return sessionId; };
	///
	///	@synopsis Update a session value 
	///	@overview Update the session value for a given key.
	///	@param key The name of the session data item to update.
	///	@param value The value of the session data item.
	void			setSessionData(char *key, char *value);
	///
	///	@synopsis Unset a session data item.
	///	@overview Unset and undefine a session data item.
	///	@param key The name of the session data item to update.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	int				unsetSessionData(char *key);
#endif

#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { 
		mutex->lock(); 
		inUse++;
	};
	inline void		unlock() { 
		if (--inUse == 0 && flags & MPR_HTTP_CONN_CLOSED) {
			delete this;
		} else {
			mutex->unlock(); 
		}
	};
#else
	inline void		lock() { };
	inline void		unlock() { 
		if (--inUse == 0 && flags & MPR_HTTP_CONN_CLOSED) {
			delete this;
		}
	};
#endif
#if BLD_FEATURE_KEEP_ALIVE
	void			setNoKeepAlive();
#endif

	friend class	Rom;
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaHandler //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Handler Flags
//
#define	MPR_HANDLER_DELETE		0x1			// Support DELETE requests
#define	MPR_HANDLER_GET			0x2			// Support GET requests
#define	MPR_HANDLER_HEAD		0x4			// Support HEAD requests
#define	MPR_HANDLER_OPTIONS		0x8			// Support OPTIONS requests
#define	MPR_HANDLER_POST		0x10		// Support POST requests
#define	MPR_HANDLER_PUT			0x20		// Support PUT requests
#define	MPR_HANDLER_TRACE		0x40		// Support TRACE requests
#define	MPR_HANDLER_NEED_ENV	0x80		// Create environment
#define	MPR_HANDLER_TERMINAL	0x100		// Terminates run processing
#define	MPR_HANDLER_ALWAYS		0x200		// Always match
#define	MPR_HANDLER_MAP_VIRTUAL	0x400		// Don't map to physical storage
#define	MPR_HANDLER_ALL	\
	(MPR_HANDLER_GET | MPR_HANDLER_POST | MPR_HANDLER_DELETE | \
	 MPR_HANDLER_PUT | MPR_HANDLER_OPTIONS | MPR_HANDLER_TRACE)

//
//	Handler run() return codes
//
#define MPR_HTTP_HANDLER_FINISHED_PROCESSING	1

///
///	@brief Base class used by all request handlers
///	
/// Handlers are used to process client HTTP requests in a modular fashion.
///	A handler may \em match a request by URL extension or by a custom 
///	matchRequest method.
///
class MaHandler : public MprLink {
  protected:
	MaHost			*host;							// Host for this handler	
	MprStringList	extList;						// Extensions served 
	MprStr			extensions;						// String ext list
	int				flags;
	MprStr			name;
	long			hitCount;						// Usage counter 

  public:
					MaHandler(char *name);
					MaHandler(char *name, char *ext, int flags);
	virtual			~MaHandler();
	MprStringList	*getExtList() { return &extList; };
	char			*getExtensions() { return extensions; };
	int				getFlags() { return flags; };
	char			*getName() { return name; };

	virtual	MaHandler 
					*cloneHandler();
	virtual int		matchRequest(MaRequest *rq, char *uri, int uriLen);
	virtual int		parseConfig(char *key, char *value, MaServer *server, 
						MaHost *host, MaAuth *auth, MaDir* dir, 
						MaLocation *location);
	virtual void	postData(MaRequest *rq, char *buf, int buflen);
	virtual int		run(MaRequest *rq);
	virtual int		setup(MaRequest *rq);

	friend class	MaHost;
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// MaRom ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_ROMFS || DOXYGEN
///
///	@brief Definition for each file in the ROM file system.
///
///	A RomInode is created for each file in the Rom file system.
///
class MaRomInode {
  public:
	MprStr			path;				// File path
	uchar			*data;				// Pointer to file data
	int				size;				// Size of file
	int				num;				// Inode number;
};

/// @brief Serve web pages and files from ROM.
///
///	The Rom file system allows web pages and configuration files to be compiled
///	so a disk based file system is not required.
///

class MaRomFileSystem : public MprFileSystem {
  private:
	MprHashTable	*fileIndex;
	MaRomInode		*romInodes;
	MprStr			root;
	int				rootLen;

  public:
					MaRomFileSystem(MaRomInode *inodeList);
					~MaRomFileSystem();
	MprHashTable		*getFiles() { return fileIndex; };
	bool			isDir(char *path);
	MaRomInode		*lookup(char *path);
	MprFile			*newFile();
	void			setRoot(char *path);
	int				stat(char *path, MprFileInfo *info);
};

//
//	Run-time hash lookup entry for each file
//
class MaRomHashEntry : public MprHashEntry {
  private:
	MaRomInode		*inode;				///< File inode descriptor
  public:
					MaRomHashEntry(char *key, MaRomInode *ri);
					~MaRomHashEntry() {};
	MaRomInode		*getInode();
};

//
//	File descriptor for a file in a Rom file system
//
class MaRomFile : public MprFile {
  private:
	MaRomFileSystem	
					*romFileSystem;
	MaRomInode		*inode;
	int				pos;						///< Current read position 
	Rom*			rom;

  public:
					MaRomFile(MaRomFileSystem* romFileSystem);
					~MaRomFile();
	int				open(char *path, int flags, int mode);
	void			close();
	int				read(void *buf, int len);
	int				write(void *buf, int len);
	long			lseek(long offset, int origin);
	int				stat(char *path, MprFileInfo *info);
};

#endif // BLD_FEATURE_ROMFS

///////////////////////////////// Prototypes ///////////////////////////////////

extern MaHttp *maGetHttp();

////////////////////////////////////////////////////////////////////////////////
#endif // _h_HTTP 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
