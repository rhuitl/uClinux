///
///	@file 	server.cpp
/// @brief 	Server Class to manage a single server
///
///	An instance of the MaServer Class may be created for each http.conf file.
///	Each server can manage multiple hosts (standard, virtual or SSL). This
///	file parses the http.conf file and creates all the necessary MaHost, MaDir
///	and MaLocation objects to manage the server's operation.
///
///	For convenience, the MaHostAddress, MaListen and MaVhost classes are 
///	contained in this file.
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

#include	"http.h"

#if BLD_FEATURE_SSL_MODULE
#include	"sslModule.h"
#endif

//////////////////////////////////// Locals ////////////////////////////////////

struct ConfigStack {
	MaLocation	*location;
	MaDir		*dir;
	MaHost		*host;
};

MaServer	*MaServer::defaultServer;

////////////////////////////// Forward Declarations ////////////////////////////

static void	acceptWrapper(void *data, MprSocket *sock, char *ipAddr, int port, 
				MprSocket *lp, int isPoolThread);
static void mapPathDelim(char *s);

#if BLD_FEATURE_DLL
static int 	locateModule(MprFileSystem *fileSystem, MaHost *host, 
				char *pathBuf, int pathSize, char *moduleDirs, char *module);
#endif

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// Server /////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaServer::MaServer(MaHttp *hs, char *name, char *serverRoot)
{
	this->name = mprStrdup(name);
	this->serverRoot = mprStrdup(serverRoot);
	http = hs;
	fileSystem = defaultFileSystem = new MprFileSystem();
	http->insertServer(this);
	hostAddresses = new MprHashTable(53);
	defaultHost = 0;
	lineNumber = 0;
#if BLD_FEATURE_LOG
	alreadyLogging = 0;
	tMod = new MprLogModule("httpServer");
#endif
	if (defaultServer == 0) {
		defaultServer = this;
	}
}

////////////////////////////////////////////////////////////////////////////////

MaServer::~MaServer()
{
	MaHost		*hp, *nextHp;
	MaListen	*lp, *nextLp;

	delete hostAddresses;
	delete defaultFileSystem;

	lp = (MaListen*) listens.getFirst();
	while (lp) {
		nextLp = (MaListen*) listens.getNext(lp);
		listens.remove(lp);
		delete lp;
		lp = nextLp;
	}

	hp = (MaHost*) hosts.getFirst();
	while (hp) {
		nextHp = (MaHost*) hosts.getNext(hp);
		hosts.remove(hp);
		delete hp;
		hp = nextHp;
	}

	mprFree(name);
	mprFree(serverRoot);

#if BLD_FEATURE_LOG
	delete tMod;
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaServer *MaServer::getDefaultServer()
{
	return defaultServer;
}

////////////////////////////////////////////////////////////////////////////////

void MaServer::setDefaultServer(MaServer *server)
{
	defaultServer = server;
}

////////////////////////////////////////////////////////////////////////////////

int MaServer::start()
{
	MaHost		*hp;
	MaListen	*lp;
	int			count;

	//
	//	Start the hosts
	//
	hp = (MaHost*) hosts.getFirst();
	while (hp) {
		mprLog(MPR_CONFIG, "Starting host named: %s\n", hp->getName());
		if (hp->start() < 0) {
			return MPR_ERR_CANT_INITIALIZE;
		}
		hp = (MaHost*) hosts.getNext(hp);
	}

	//
	//	Listen to all required ipAddr:ports
	//
	count = 0;
	lp = (MaListen*) listens.getFirst();
	while (lp) {
		if (lp->open(this) < 0) {
			mprError(MPR_L, MPR_USER, "Can't listen for HTTP on %s:%d\n", 
				lp->getIpAddr(), lp->getPort());
		} else {
			mprLog(MPR_CONFIG, "Listening for HTTP on %s:%d %s\n", 
				lp->getIpAddr(), lp->getPort(),
#if BLD_FEATURE_SSL_MODULE
				lp->isSecure() ? "(secure)" : "");
#else
				"");
#endif
			count++;
		}
		lp = (MaListen*) listens.getNext(lp);
	}
	if (count == 0) {
		mprError(MPR_L, MPR_USER, "Server is not listening on any addresses\n");
		return MPR_ERR_CANT_OPEN;
	}

	//
	//	Now change user and group to the desired identities (user must be last)
	//
	if (http->changeGroup() < 0 || http->changeUser() < 0) {
		return MPR_ERR_CANT_COMPLETE;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaServer::stop()
{
	MaHost		*hp;
	MaListen	*lp;

	lp = (MaListen*) listens.getFirst();
	while (lp) {
		lp->close();
		lp = (MaListen*) listens.getNext(lp);
	}

	hp = (MaHost*) hosts.getFirst();
	while (hp) {
		hp->stop();
		hp = (MaHost*) hosts.getNext(hp);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Max stack depth is:
//		Default Server			Level 1
//			<VirtualHost>		Level 2
//				<Directory>		Level 3
//					<Location>	Level 4
//

int MaServer::configure(char *configFile, bool outputConfig)
{
#if BLD_FEATURE_CONFIG
	ConfigStack		stack[4];
	MprFile			*file;
	MaHostAddress	*address;
	MaListen		*lp;
	MaDir			*dir;
	MaHost			*host;
	bool			needServerName, natServerName;
	char			buf[MPR_MAX_STRING], pathBuf[MPR_MAX_FNAME];
	char			pathBuf2[MPR_MAX_FNAME], ipAddrPort[MPR_MAX_IP_ADDR_PORT];
	char			*cp, *tok, *key, *value;
	int				i, rc, top;

	top = 0;
	memset(stack, 0, sizeof(stack));

#if BLD_FEATURE_LOG
	alreadyLogging = mprGetMpr()->logService->isLogging();
#endif

	file = fileSystem->newFile();
	if (file->open(configFile, O_RDONLY | O_TEXT, 0444) < 0) {
		mprError(MPR_L, MPR_USER, "Can't open %s for config directives\n", 
			configFile);
		delete file;
		return MPR_ERR_CANT_OPEN;
	}

	//
	//	Create the default host and directory
	//
	defaultHost = host = stack[top].host = new MaHost(this);
	hosts.insert(host);
	stack[top].dir = new MaDir();
	host->insertDir(stack[top].dir);
	host->setName("Main Server");

	getcwd(pathBuf, sizeof(pathBuf) - 1);
	mprLog(MPR_CONFIG, "Current Directory: \n"
		"                       \"%s\"\n", pathBuf);

	//
	//	Parse each line in http.conf
	//
	for (lineNumber = 1; file->gets(buf, sizeof(buf) - 1); lineNumber++) {
		buf[sizeof(buf) - 1] = '\0';
		cp = buf;
		while (isspace(*cp)) {
			cp++;
		}
		if (*cp == '\0' || *cp == '#') {
			continue;
		}
		key = mprStrTok(cp, " \t\n", &tok);
		value = mprStrTok(0, "\n", &tok);
		if (key == 0 || *key == '\0') {
			goto err;
		}
		if (value) {
			while (isspace(*value)) {
				value++;
			}
			if (*value) {
				cp = &value[strlen(value) - 1];
				while (cp > value && isspace(*cp)) {
					cp--;
				}
				*++cp = '\0';
			}
		}

		if (*key != '<') {
			//
			//	Keywords outside of a virtual host or directory section
			//
			rc = processSetting(key, value, stack[top].host, stack[top].dir, 
				stack[top].location);
			if (rc == MPR_ERR_BAD_SYNTAX) {
				mprError(MPR_L, MPR_USER, 
					"Error with \"%s\" at line %d in %s", key, lineNumber, 
					configFile);
				goto err;
			}
			continue;
		}
		
		//
		//	Directory, Location and virtual host sections
		//
		key++;
		i = strlen(key) - 1;
		if (key[i] == '>') {
			key[i] = '\0';
		}
		if (*key != '/') {
			i = strlen(value) - 1;
			if (value[i] == '>') {
				value[i] = '\0';
			}
			//
			//	Opening tags
			//
			if (mprStrCmpAnyCase(key, "VirtualHost") == 0) {
				//
				//	Do not inherit directories or locations
				//
				top++;
				stack[top].host = host = new MaHost(this);
				stack[top].location = 0;
				stack[top].dir = new MaDir();
				stack[top].dir->inheritUserGroup(stack[top - 1].dir->getAuth());

				hosts.insert(host);
				host->setVhost();
				host->insertDir(stack[top].dir);

				if (createHostAddresses(host, value) < 0) {
					hosts.remove(host);
					delete host;
					goto err;
				}

				host->copyHandlers(defaultHost);

			} else if (mprStrCmpAnyCase(key, "Directory") == 0) {
				if (stack[top].location != 0) {
					mprError(MPR_L, MPR_USER, 
						"Can't nest Directory directive inside a Location "
						"directive");
					goto err;
				}
				host->replaceReferences(pathBuf2, sizeof(pathBuf2), value);
				if (host->makePath(pathBuf, sizeof(pathBuf), pathBuf2) == 0) {
					mprError(MPR_L, MPR_LOG, "Directory path is too long");
					goto err;
				}

				//
				//	Create a new directory inherit parent directory settings
				//	This means inherit authorization from the enclosing host
				//
				top++;
				stack[top].host = stack[top - 1].host;
				stack[top].location = 0;

				if ((dir = host->findDir(pathBuf)) != 0) {
					stack[top].dir = dir;
				} else {
					stack[top].dir = new MaDir(stack[top - 1].dir, 
						stack[top - 1].dir->getAuth());
					stack[top].dir->setPath(pathBuf);
					host->insertDir(stack[top].dir);
				}

			} else if (mprStrCmpAnyCase(key, "Location") == 0) {
				//
				//	Inherit authorization from the enclosing directory
				//
				top++;
				stack[top].host = stack[top - 1].host;
				stack[top].dir = stack[top - 1].dir;
				stack[top].location = new MaLocation(stack[top].dir->getAuth());

				stack[top].location->setPrefix(value);
				if (host->insertLocation(stack[top].location) < 0) {
					mprError(MPR_L, MPR_USER, "Can't add location %s\n", value);
					goto err;
				}
			}

		} else {
			key++;
			//
			//	Closing tag
			//
			if (mprStrCmpAnyCase(key, "VirtualHost") == 0) {
				top--;
				host = stack[top].host;

			} else if (mprStrCmpAnyCase(key, "Directory") == 0) {
				top--;

			} else if (mprStrCmpAnyCase(key, "Location") == 0) {
				top--;
			}
			if (top < 0) {
				goto err;
			}
		}
	}

	//
	//	Validate configuration -- FUTURE split this function
	//
	if (listens.getFirst() == 0) {
		mprError(MPR_L, MPR_CONFIG, "Must have a Listen directive");
		goto err;
	}
	if (http->getHandlerServicesCount() == 0) {
		mprError(MPR_L, MPR_CONFIG, "Must have at least one handler defined");
		goto err;
	}

	if (defaultHost->getMimeTypes() == 0) {
		if (host->openMimeTypes("mime.types") < 0) {
			mprError(MPR_L, MPR_CONFIG, "Missing valid mime.types");
			goto err;
		}
	}

	//
	//	FUTURE -- should test here that all location handlers are defined
	//
#if MPR_FEATURE_MULTITHREAD
	MaLimits *limits = http->getLimits();
	if (limits->maxThreads > 0) {
		mprGetMpr()->setMaxPoolThreads(limits->maxThreads);
		mprGetMpr()->setMinPoolThreads(limits->minThreads);
	}
#endif

#if UNUSED
#if BLD_FEATURE_KEEP_ALIVE
	//
	//	Set some defaults incase http.conf has missing directives
	//
	if (defaultHost->getKeepAlive() < 0) {
		defaultHost->setKeepAlive(1);
	}
	if (defaultHost->getKeepAliveTimeout() < 0) {
		 defaultHost->setKeepAliveTimeout(MPR_HTTP_KEEP_TIMEOUT);
	}
	if (defaultHost->getMaxKeepAlive() < 0) {
		defaultHost->setMaxKeepAlive(MPR_HTTP_MAX_KEEP_ALIVE);
	}
#endif
	if (defaultHost->getTimeout() < 0) {
		defaultHost->setTimeout(MPR_HTTP_SERVER_TIMEOUT);
	}
	if (defaultHost->getHttpVersion() == 0) {
		defaultHost->setHttpVersion(MPR_HTTP_1_1);
	}
#endif


	//
	//	Add default server listening addresses to the HostAddress hash.
	//	We pretend it is a vhost. Insert at the end of the vhost list so we
	//	become the default if no other vhost matches. Ie. vhosts take precedence
	//	At the same time, define a ServerName if one has not been defined. We
	//	take the first non loopback listening address.
	//
	natServerName = 0;
	needServerName = strcmp(defaultHost->getName(), "Main Server") == 0;
	lp = (MaListen*) listens.getFirst();
	while (lp) {
		mprSprintf(ipAddrPort, sizeof(ipAddrPort), "%s:%d", 
			lp->getIpAddr(), lp->getPort());
		address = (MaHostAddress*) hostAddresses->lookup(ipAddrPort);
		if (address == 0) {
			address = new MaHostAddress(ipAddrPort);
			hostAddresses->insert(address);
		}
		address->insertVhost(new MaVhost(defaultHost));
		if (needServerName) {
			//
			// 	Try to get the most accessible server name possible.
			//
			if (strncmp(ipAddrPort, "127.", 4) == 0 ||
					strncmp(ipAddrPort, "localhost:", 10) == 0) {
				if (! natServerName) {
					defaultHost->setName(ipAddrPort);
				}
			} else {
				if (strncmp(ipAddrPort, "10.", 3) == 0 ||
					strncmp(ipAddrPort, "192.168.", 8) == 0 ||
					strncmp(ipAddrPort, "172.16.", 7) == 0) {
					if (! natServerName) {
						defaultHost->setName(ipAddrPort);
						natServerName = 1;
					}
				} else {
					defaultHost->setName(ipAddrPort);
					needServerName = 0;
				}
			}
		}
		lp = (MaListen*) listens.getNext(lp);
	}

	//
	//	Last try to setup the server name if we don't have a non-local name.
	//
	if (needServerName && !natServerName) {
#if UNUSED
		//
		//	This code is undesirable as it makes us dependent on DNS -- bad
		//
		mprLog(0, 
			"WARNING: Missing ServerName directive, doing DNS lookup.\n");
		char *hostName = mprGetMpr()->getServerName();
		mprSprintf(ipAddrPort, sizeof(ipAddrPort), "%s:%d", 
			hostName, ((MaListen*) listens.getFirst())->getPort());
		defaultHost->setName(hostName);
#endif
		defaultHost->setName(defaultHost->getIpAddr());
	}
	mprLog(2, tMod, "ServerName set to: %s\n", defaultHost->getName());

	if (defaultHost->getDocumentRoot() == 0) {
		mprError(MPR_L, MPR_LOG, "Host %s is missing a DocumentRoot directive", 
			defaultHost->getName());
		goto err;
	}

	//
	//	Propagate some configuration settings to the virtual hosts
	//
	host = (MaHost*) hosts.getNext(defaultHost);
	while (host) {
		//
		//	Name must be set as the default host will be set above. 
		//	Virtual host names default to the ip address
		//
		mprAssert(host->getName() != 0);
		if (host->getDocumentRoot() == 0) {
			mprError(MPR_L, MPR_LOG, 
				"Host %s is missing a DocumentRoot directive", host->getName());
			goto err;
		}
		if (host->getMimeTypes() == 0) {
			host->setMimeTypes(defaultHost->getMimeTypes());
		}
#if BLD_FEATURE_ACCESS_LOG
		if (host->getLogFd() < 0) {
			host->setLogHost(defaultHost);
		}
#endif
#if BLD_FEATURE_KEEP_ALIVE
		if (host->getKeepAlive() == -1) {
			host->setKeepAlive(defaultHost->getKeepAlive());
			host->setKeepAliveTimeout(defaultHost->getKeepAliveTimeout());
			host->setMaxKeepAlive(defaultHost->getMaxKeepAlive());
		}
#endif
		if (host->getTimeout() < 0) {
			host->setTimeout(defaultHost->getTimeout());
		}
		if (host->getHttpVersion() == 0) {
			host->setHttpVersion(defaultHost->getHttpVersion());
		}

		host = (MaHost*) hosts.getNext(host);
	}

	if (outputConfig) {
		displayConfig();
	}

	file->close();
	delete file;
	return 0;

err:
	mprError(MPR_L, MPR_LOG, "Syntax error in %s at line %d", 
		configFile, lineNumber);
	file->close();
	delete file;
	return MPR_ERR_BAD_SYNTAX;
#else
	mprError(MPR_L, MPR_USER, "%s has been built without BLD_FEATURE_CONFIG\n"
		"You must configure the server using API calls", BLD_NAME);
	return MPR_ERR_CANT_INITIALIZE;
#endif
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_CONFIG
//
//	Process the configuration settings. Permissible to modify key and value.
//
//	FUTURE -- this function is quite big. Could be subject to a FEATURE.
//

int MaServer::processSetting(char *key, char *value, MaHost *host, MaDir *dir,
	MaLocation *location)
{
	MaAuth			*auth;
	MaAlias			*ap;
	MprList			*ipList;
	MaHandlerService *hs;
	MaHandler		*handler;
	MprInterface	*ip;
	MaModule		*module;
	MaLocation		*lp;
	MprList			*handlerList;
	MprList			*moduleList;
	MaLimits		*limits;
	MaDir			*dp;
	char			addrBuf[MPR_MAX_IP_ADDR_PORT];
	char			pathBuf[MPR_MAX_FNAME], pathBuf2[MPR_MAX_FNAME];
	char			*name, *path, *prefix, *cp, *tok, *ext, *mimeType;
	char			*url, *newUrl, *from, *spec, *extensions;
	int				port, rc, code, processed, num;

	mprAssert(key);
	mprAssert(host);
	mprAssert(dir);

	auth = (location ? location->getAuth() : dir->getAuth());
	processed = 0;
	limits = host->getLimits();

	switch (toupper(key[0])) {
	case 'A':
		//
		//	All these string compares are not quick, but this is only done once
		//	at startup time.
		//
		if (mprStrCmpAnyCase(key, "Alias") == 0) {
			// Scope: server, host
			if (splitValue(&prefix, &path, value, 1) < 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			host->replaceReferences(pathBuf, sizeof(pathBuf), path);
			if (host->makePath(pathBuf2, sizeof(pathBuf2), pathBuf) == 0) {
				mprError(MPR_L, MPR_LOG, "Alias path is too long");
				return MPR_ERR_BAD_SYNTAX;
			}
			if (prefix[strlen(prefix) - 1] == '/' && 
				pathBuf2[strlen(pathBuf2) - 1] != '/') {
				mprError(MPR_L, MPR_LOG, 
					"May be missing a trailing '/' on the Alias path %s."
					"In configuration file at line %d\n", path, lineNumber);
			}
			if (host->findDir(pathBuf2) == 0) {
				dp = new MaDir(dir, dir->getAuth());
				dp->setPath(pathBuf2);
				host->insertDir(dp);
			}
			ap = new MaAlias(prefix, pathBuf2);
			mprLog(4, tMod, "Alias: \"%s\":\n\t\t\t\"%s\"\n", 
				prefix, pathBuf2);
			if (host->insertAlias(ap) < 0) {
				mprError(MPR_L, MPR_LOG, "Can't add alias %s %s", prefix, 
					pathBuf2); 
				return MPR_ERR_ALREADY_EXISTS;
			}
			return 1;

		} else if (mprStrCmpAnyCase(key, "AddHandler") == 0) {
			// Scope: server, host, directory
			name = mprStrTok(value, " \t", &extensions);
			hs = http->lookupHandlerService(name);
			if (hs == 0) {
				mprError(MPR_L, MPR_LOG, "Can't find handler %s", name); 
				return MPR_ERR_NOT_FOUND;
			}
			if (extensions == 0 || *extensions == '\0') {
				mprLog(MPR_CONFIG, "Add %s\n", name);
				host->insertHandler(hs->newHandler(this, host, 0));
			} else {
				mprLog(MPR_CONFIG, "Add %s for \"%s\"\n", name, extensions);
				host->insertHandler(hs->newHandler(this, host, extensions));
			}
			return 1;

		} else if (mprStrCmpAnyCase(key, "AddType") == 0) {
			if (splitValue(&mimeType, &ext, value, 1) < 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			host->addMimeType(ext, mimeType);
			return 1;

		} else if (mprStrCmpAnyCase(key, "Allow") == 0) {
			if (splitValue(&from, &spec, value, 1) < 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			// spec can be: all, host, ipAddr
			auth->setAllowSpec(spec);
			return 1;
		}
		break;

	case 'B':
		if (mprStrCmpAnyCase(key, "BrowserMatch") == 0) {
			return 1;
		}
		break;

	case 'C':
#if BLD_FEATURE_ACCESS_LOG
		if (mprStrCmpAnyCase(key, "CustomLog") == 0) {
			char *format;
			path = mprStrTok(value, " \t", &format);
			if (path == 0 || format == 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			path = mprStrTrim(path, '\"');
			if (host->makePath(pathBuf, sizeof(pathBuf), path) == 0) {
				mprError(MPR_L, MPR_LOG, "CustomLog path is too long");
				return MPR_ERR_BAD_SYNTAX;
			}
			host->setLog(pathBuf, mprStrTrim(format, '\"'));
			host->setLogHost(host);
			return 1;
		}
#endif
		break;

	case 'D':
		if (mprStrCmpAnyCase(key, "Deny") == 0) {
			if (splitValue(&from, &spec, value, 1) < 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			auth->setDenySpec(spec);
			return 1;

		} else if (mprStrCmpAnyCase(key, "DirectoryIndex") == 0) {
			value = mprStrTrim(value, '\"');
			if (dir == 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			dir->setIndex(value);
			return 1;

		} else if (mprStrCmpAnyCase(key, "DocumentRoot") == 0) {
			value = mprStrTrim(value, '\"');
			if (dir->getPath() != 0) {
				mprError(MPR_L, MPR_LOG, 
					"DocumentRoot is already defined to be %s", pathBuf);
				return MPR_ERR_BAD_SYNTAX;
			}
			if (host->makePath(pathBuf, sizeof(pathBuf), value, 1) == 0) {
				mprError(MPR_L, MPR_LOG, "DocumentRoot is too long");
				return MPR_ERR_BAD_SYNTAX;
			}
			if (! fileSystem->isDir(pathBuf)) {
				mprError(MPR_L, MPR_LOG, "Can't access DocumentRoot directory");
				return MPR_ERR_BAD_SYNTAX;
			}
			host->setDocumentRoot(pathBuf);
			dir->setPath(pathBuf);
			mprLog(MPR_CONFIG, "Document Root for %s:\n"
				"                       \"%s\"\n", host->getName(), pathBuf);
			return 1;
		}
		break;

	case 'E':
		if (mprStrCmpAnyCase(key, "ErrorLog") == 0) {
			path = mprStrTrim(value, '\"');
			if (path && *path) {
#if BLD_FEATURE_LOG
				if (alreadyLogging) {
					mprLog(2, tMod,
						"Already logging. Ignoring ErrorLog directive\n");
				} else {
					mprGetMpr()->logService->stop();
					if (host->makePath(pathBuf, sizeof(pathBuf), path) == 0) {
						mprError(MPR_L, MPR_LOG, "ErrorLog path is too long");
						return MPR_ERR_BAD_SYNTAX;
					}
					if (strlen(pathBuf) < sizeof(pathBuf) - 3) {
						strcat(pathBuf, ":2");
					}
					if (mprGetMpr()->logService->setLogSpec(pathBuf) < 0) {
						mprFprintf(MPR_STDERR, "Can't log errors to %s\n", 
							pathBuf);
						return MPR_ERR_BAD_SYNTAX;
					}
					mprGetMpr()->logService->start();
				}
#endif
			}
			return 1;
		}
		break;

	case 'G':
		if (mprStrCmpAnyCase(key, "Group") == 0) {
			value = mprStrTrim(value, '\"');
			http->setGroup(value);
			return 1;
		}
		break;

	case 'K':
#if BLD_FEATURE_KEEP_ALIVE
		if (mprStrCmpAnyCase(key, "KeepAlive") == 0) {
			if (mprStrCmpAnyCase(value, "on") == 0) {
				host->setKeepAlive(1);
			} else {
				host->setKeepAlive(0);
			}
			mprLog(3, tMod, "Host %s, %s: %s\n", host->getName(), key, value);
			return 1;

		} else if (mprStrCmpAnyCase(key, "KeepAliveTimeout") == 0) {
			host->setKeepAliveTimeout(atoi(value) * 1000);
			return 1;
		}
#endif
		break;
	
	case 'L':
		if (mprStrCmpAnyCase(key, "LimitRequestBody") == 0) {
			num = atoi(value);
			if (num < MPR_HTTP_BOT_BODY || num > MPR_HTTP_TOP_BODY) {
				return MPR_ERR_BAD_SYNTAX;
			}
			limits->maxBody = num;
			return 1;

		} else if (mprStrCmpAnyCase(key, "LimitRequestFields") == 0) {
			num = atoi(value);
			if (num < MPR_HTTP_BOT_NUM_HEADER || num > MPR_HTTP_TOP_NUM_HEADER){
				return MPR_ERR_BAD_SYNTAX;
			}
			limits->maxNumHeader = num;
			return 1;

		} else if (mprStrCmpAnyCase(key, "LimitRequestFieldSize") == 0) {
			num = atoi(value);
			if (num < MPR_HTTP_BOT_HEADER || num > MPR_HTTP_TOP_HEADER){
				return MPR_ERR_BAD_SYNTAX;
			}
			limits->maxHeader = num;
			return 1;

		} else if (mprStrCmpAnyCase(key, "LimitRequestLine") == 0) {
			num = atoi(value);
			if (num < MPR_HTTP_BOT_FIRST_LINE || num > MPR_HTTP_TOP_FIRST_LINE){
				return MPR_ERR_BAD_SYNTAX;
			}
			limits->maxFirstLine = num;
			return 1;

		} else if (mprStrCmpAnyCase(key, "LimitResponseBody") == 0) {
			num = atoi(value);
			if (num < MPR_HTTP_BOT_RESPONSE_BODY || 
					num > MPR_HTTP_TOP_RESPONSE_BODY) {
				return MPR_ERR_BAD_SYNTAX;
			}
			limits->maxResponseBody = num;
			return 1;

		} else if (mprStrCmpAnyCase(key, "LimitUrl") == 0) {
			num = atoi(value);
			if (num < MPR_HTTP_BOT_URL || num > MPR_HTTP_TOP_URL){
				return MPR_ERR_BAD_SYNTAX;
			}
			limits->maxUrl = num;
			return 1;

		} else if (mprStrCmpAnyCase(key, "Listen") == 0) {
			//
			//	Options:
			//		ipAddr:port
			//		ipAddr			default port 80
			//		port			All ip interfaces on this port
			//
			if ((cp = strchr(value, ':')) != 0) {
				if (host->getIpAddr() == 0) {
					host->setIpAddr(value);
				}
				*cp++ = '\0';
				port = atoi(cp);
				if (port <= 0 || port > 65535) {
					mprError(MPR_L, MPR_LOG, "Bad listen port number %d", port);
					return MPR_ERR_BAD_SYNTAX;
				}
				listens.insert(new MaListen(value, atoi(cp)));

			} else {
				if (isdigit(*value) && strchr(value, '.') == 0) {
					ipList = mprGetMpr()->socketService->getInterfaceList();
					ip = (MprInterface*) ipList->getFirst();
					if (ip == 0) {
						port = atoi(value);
						listens.insert(new MaListen("localhost", port));
						if (host->getIpAddr() == 0) {
							mprSprintf(addrBuf, sizeof(addrBuf), 
								"localhost:%d", port);
							host->setIpAddr(addrBuf);
						}
					} else {
						port = atoi(value);
						if (port <= 0 || port > 65535) {
							mprError(MPR_L, MPR_LOG, 
								"Bad listen port number %d", port);
							return MPR_ERR_BAD_SYNTAX;
						}
						while (ip) {
							listens.insert(new MaListen(ip->ipAddr, port));
							if (host->getIpAddr() == 0) {
								mprSprintf(addrBuf, sizeof(addrBuf), "%s:%d", 
									ip->ipAddr, port);
								host->setIpAddr(addrBuf);
							}
							ip = (MprInterface*) ipList->getNext(ip);
						}
					}
				} else {
					listens.insert(new MaListen(value, 80));
					if (host->getIpAddr() == 0) {
						host->setIpAddr(value);
					}
				}
			}
			return 1;

		} else if (mprStrCmpAnyCase(key, "LogFormat") == 0) {
			return 1;

		} else if (mprStrCmpAnyCase(key, "LogLevel") == 0) {
#if BLD_FEATURE_LOG
			if (alreadyLogging) {
				mprLog(2, tMod,
					"Already logging. Ignoring LogLevel directive\n");
			} else {
				value = mprStrTrim(value, '\"');
				int level = atoi(value);
				mprGetMpr()->logService->setDefaultLevel(level);
			}
#endif
			return 1;

		} else if (mprStrCmpAnyCase(key, "LoadModulePath") == 0) {
#if BLD_FEATURE_DLL
			host->setModuleDirs(value);
#endif

		} else if (mprStrCmpAnyCase(key, "LoadModule") == 0) {
			name = mprStrTok(value, " \t", &tok);
			if (name == 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			//
			//	See if the module is already statically or dynamically loaded 
			//
			module = http->findModule(name);
			if (module == 0) {
#if BLD_FEATURE_DLL
				void *handle;
				char withExtBuf[MPR_MAX_FNAME];
				char entryPoint[MPR_MAX_FNAME];

				path = mprStrTok(0, "\n", &tok);
				if (path == 0) {
					return MPR_ERR_BAD_SYNTAX;
				}

				//
				//	Don't validate withExtBuf as we want to allow DLLs outside
				//	of serverRoot that use leading ".."
				//
				mprSprintf(withExtBuf, sizeof(withExtBuf), "%s%s", path, 
					MPR_DLL_EXT);
				name[0] = toupper(name[0]);
				mprSprintf(entryPoint, sizeof(entryPoint), "mpr%sInit", name);

				//
				//
				//
				if (locateModule(fileSystem, host, pathBuf, sizeof(pathBuf), 
						host->getModuleDirs(), withExtBuf) < 0) {
					mprError(MPR_L, MPR_LOG, "Can't find module %s", name);
					return MPR_ERR_CANT_OPEN;
				}

				rc = mprGetMpr()->loadDll(pathBuf, entryPoint, http, 
					&handle);

				if (rc < 0) {
					if (rc == MPR_ERR_NOT_INITIALIZED) {
						mprError(MPR_L, MPR_USER, 
							"Objects are not initialized.\nPossibly loading a "
							"DLL into a statically linked program.\n"
							"You must statically link all modules.\n");	
					}
					mprError(MPR_L, MPR_LOG, "Can't load DLL %s", pathBuf);
					return MPR_ERR_BAD_SYNTAX;
				}
				mprLog(MPR_CONFIG, "Loading module (DLL) %s\n", name);
#else
				mprError(MPR_L, MPR_LOG, "Can't find module %s", name);
				return MPR_ERR_BAD_SYNTAX;
#endif
			} else {
				mprLog(MPR_CONFIG, "Activate static module %s\n", name);
			}
			return 1;
		}
		break;

	case 'M':
#if BLD_FEATURE_KEEP_ALIVE
		if (mprStrCmpAnyCase(key, "MaxKeepAliveRequests") == 0) {
			host->setMaxKeepAlive(atoi(value));
			return 1;
		}
#endif
		break;

	case 'N':
		if (mprStrCmpAnyCase(key, "NameVirtualHost") == 0) {
			createHostAddresses(0, value);
			return 1;
		}
		break;

	case 'O':
		if (mprStrCmpAnyCase(key, "Order") == 0) {
			if (mprStrCmpAnyCase(mprStrTrim(value, '\"'), "Allow,Deny") == 0) {
				auth->setOrder(MPR_HTTP_ALLOW_DENY);
			} else {
				auth->setOrder(MPR_HTTP_DENY_ALLOW);
			}
			return 1;
		}
		break;

	case 'P':
		if (mprStrCmpAnyCase(key, "Protocol") == 0) {
			if (strcmp(value, "HTTP/1.0") == 0) {
				host->setHttpVersion(MPR_HTTP_1_0);
			} else if (strcmp(value, "HTTP/1.1") == 0) {
				host->setHttpVersion(MPR_HTTP_1_1);
			}
			return 1;
		}
		break;

	case 'R':
		if (mprStrCmpAnyCase(key, "Redirect") == 0) {
			if (value[0] == '/' || value[0] == 'h') {
				code = 302;
				url = mprStrTok(value, " \t", &tok);

			} else if (isdigit(value[0])) {
				cp = mprStrTok(value, " \t", &tok);
				code = atoi(cp);
				url = mprStrTok(0, " \t\n", &tok);

			} else {
				cp = mprStrTok(value, " \t", &tok);
				if (strcmp(value, "permanent") == 0) {
					code = 301;
				} else if (strcmp(value, "temp") == 0) {
					code = 302;
				} else if (strcmp(value, "seeother") == 0) {
					code = 303;
				} else if (strcmp(value, "gone") == 0) {
					code = 410;
				} else {
					return MPR_ERR_BAD_SYNTAX;
				}
				url = mprStrTok(0, " \t\n", &tok);
			}
			if (code >= 300 && code <= 399) {
				newUrl = mprStrTok(0, "\n", &tok);
			} else {
				newUrl = "";
			}
			if (code <= 0 || url == 0 || newUrl == 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			url = mprStrTrim(url, '\"');
			newUrl = mprStrTrim(newUrl, '\"');
			mprLog(4, tMod, 
				"insertAlias: Redirect %d from \"%s\" to \"%s\"\n", 
				code, url, newUrl);
			ap = new MaAlias(url, newUrl, code);
			host->insertAlias(ap);
			return 1;

		} else if (mprStrCmpAnyCase(key, "ResetHandlers") == 0) {
			//
			//	Currently not supported
			//
//			host->deleteHandlers();
			return 1;
		}
		break;

	case 'S':
		if (mprStrCmpAnyCase(key, "ScriptAlias") == 0) {
			if (splitValue(&prefix, &path, value, 1) < 0 || path == 0 || 
					prefix == 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			//
			//	Create an alias, dir and location with a cgiHandler
			//
			host->replaceReferences(pathBuf, sizeof(pathBuf), path);
			ap = new MaAlias(prefix, pathBuf);
			mprLog(4, tMod, "ScriptAlias \"%s\":\n\t\t\t\"%s\"\n", 
				prefix, pathBuf);
			host->insertAlias(ap);
			lp = new MaLocation(dir->getAuth());
			lp->setPrefix(prefix);
			lp->setHandler("cgiHandler");
			host->insertLocation(lp);
			if (host->findDir(pathBuf) == 0) {
				dp = new MaDir(dir, dir->getAuth());
				dp->setPath(pathBuf);
				host->insertDir(dp);
			}
			return 1;

		} else if (mprStrCmpAnyCase(key, "SendBufferSize") == 0) {
			num = atoi(value);
			if (num < MPR_HTTP_BOT_SEND_BUFFER || 
					num > MPR_HTTP_TOP_SEND_BUFFER) {
				return MPR_ERR_BAD_SYNTAX;
			}
			limits->sendBufferSize = num;
			return 1;

		} else if (mprStrCmpAnyCase(key, "ServerName") == 0) {
			value = mprStrTrim(value, '\"');
			if (strncmp(value, "http://", 7) == 0) {
				host->setName(&value[7]);
			} else {
				host->setName(value);
			}
			return 1;

		} else if (mprStrCmpAnyCase(key, "ServerRoot") == 0) {
			value = mprStrTrim(value, '\"');
			if (host->makePath(pathBuf, sizeof(pathBuf), value, 1) == 0) {
				mprError(MPR_L, MPR_LOG, "ServerRoot is too long");
				return MPR_ERR_BAD_SYNTAX;
			}
			if (! fileSystem->isDir(pathBuf)) {
				mprError(MPR_L, MPR_LOG, "Can't access ServerRoot directory");
				return MPR_ERR_BAD_SYNTAX;
			}
			setServerRoot(pathBuf);
#if BLD_FEATURE_ROMFS
			mprLog(MPR_CONFIG, "Server Root \"%s\" in ROM\n", pathBuf);
#else
			mprLog(MPR_CONFIG, "Server Root \"%s\"\n", pathBuf);
#endif
			return 1;

#if BLD_FEATURE_SESSION
		} else if (mprStrCmpAnyCase(key, "SessionTimeout") == 0) {
			if (value == 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			host->setSessionTimeout(atoi(mprStrTrim(value, '\"')));
			return 1;
#endif
			
		} else if (mprStrCmpAnyCase(key, "SetHandler") == 0) {
			if (location == 0) {
				mprError(MPR_L, MPR_LOG, 
					"SetHandler only valid in Location blocks");
				return MPR_ERR_BAD_SYNTAX;
			}
			value = mprStrTrim(value, '\"');
			if (host->lookupHandler(value) == 0) {
				mprError(MPR_L, MPR_LOG, "Can't find handler %s", value);
				return MPR_ERR_BAD_SYNTAX;
			}
			location->setHandler(mprStrTrim(value, '\"'));
			return 1;

#if UNUSED
		} else if (mprStrCmpAnyCase(key, "SSLEngine") == 0) {
#if BLD_FEATURE_SSL_MODULE
			if (mprStrCmpAnyCase(value, "on") == 0) {
				hs = http->lookupHandlerService("sslHandler");
				if (hs == 0) {
					mprError(MPR_L, MPR_LOG, "Can't find ssl handler"); 
					return MPR_ERR_NOT_FOUND;
				}
				host->insertHandler(hs->newHandler(this, host, 0));
				host->setSecure(1);
			}
#endif
			return 1;
#endif

		} else if (mprStrCmpAnyCase(key, "StartThreads") == 0) {
#if BLD_FEATURE_MULTITHREAD
			num = atoi(value);
			if (num < 0 || num > MPR_HTTP_TOP_THREADS) {
				return MPR_ERR_BAD_SYNTAX;
			}
			limits->minThreads = num;
#endif
			return 1;
		}
		break;

	case 'T':
		if (mprStrCmpAnyCase(key, "ThreadLimit") == 0) {
#if BLD_FEATURE_MULTITHREAD
			num = atoi(value);
			if (num < 0 || num > MPR_HTTP_TOP_THREADS) {
				return MPR_ERR_BAD_SYNTAX;
			}
			limits->maxThreads = num;
#endif
			return 1;

		} else if (mprStrCmpAnyCase(key, "ThreadStackSize") == 0) {
#if BLD_FEATURE_MULTITHREAD
			num = atoi(value);
			if (num < MPR_HTTP_BOT_STACK || num > MPR_HTTP_TOP_STACK) {
				return MPR_ERR_BAD_SYNTAX;
			}
			mprGetMpr()->poolService->setStackSize(num);
			return 1;
#endif

		} else if (mprStrCmpAnyCase(key, "TimeOut") == 0) {
			host->setTimeout(atoi(value) * 1000);
			return 1;

		} else if (mprStrCmpAnyCase(key, "TypesConfig") == 0) {
			path = mprStrTrim(value, '\"');
			if (host->makePath(pathBuf, sizeof(pathBuf), path, 1) == 0) {
				mprError(MPR_L, MPR_LOG, "TypesConfig path is too long");
				return MPR_ERR_BAD_SYNTAX;
			}
			if (host->openMimeTypes(pathBuf) < 0) {
				return MPR_ERR_BAD_SYNTAX;
			}
			return 1;
		}
		break;
	
	case 'U':
		if (mprStrCmpAnyCase(key, "User") == 0) {
			http->setUser(mprStrTrim(value, '\"'));
			return 1;
		}
		break;
	}

	handlerList = host->getHandlers();
	handler = (MaHandler*) handlerList->getFirst();
	while (handler) {
		rc = handler->parseConfig(key, value, this, host, auth, dir, location);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			break;
		}
		handler = (MaHandler*) handlerList->getNext(handler);
	}

	moduleList = http->getModules();
	module = (MaModule*) moduleList->getFirst();
	while (module) {
		rc = module->parseConfig(key, value, this, host, auth, dir, location);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			break;
		}
		module = (MaModule*) moduleList->getNext(module);
	}
	return 0;
}

#endif // BLD_FEATURE_CONFIG
////////////////////////////////////////////////////////////////////////////////
//
//	Called for hosts or for NameVirtualHost directives (host == 0)
//

int MaServer::createHostAddresses(MaHost *host, char *value)
{
	MaListen		*lp, *nextLp;
	MaHostAddress	*address;
	char			*ipAddr, *cp, *tok;
	char			addrBuf[MPR_MAX_IP_ADDR_PORT];
	int				port;

	address = 0;
	ipAddr = mprStrTok(value, " \t", &tok);

	//
	//	Define a default name for the host. The Name Will be overridden by any
	//	ServerName directives (necessary for named virtual hosts). The ipAddr
	//	will be preserved.
	//
	if (host) {
		host->setIpAddr(ipAddr);
		host->setName(ipAddr);
	}

	while (ipAddr) {
		if (mprStrCmpAnyCase(ipAddr, "_default_") == 0) {
			ipAddr = "*:*";
		}

		port = -1;
		if ((cp = strchr(ipAddr, ':')) != 0) {
			*cp++ = '\0';
			if (*cp != '*') {
				port = atoi(cp);
			}
		}

		lp = (MaListen*) listens.getFirst();
		while (lp) {
			nextLp = (MaListen*) listens.getNext(lp);
			if (port > 0 && port != lp->getPort()) {
				lp = nextLp;
				continue;
			}
			if (ipAddr[0] != '*' && strcmp(ipAddr, lp->getIpAddr()) != 0) {
				lp = nextLp;
				continue;
			}
			mprSprintf(addrBuf, sizeof(addrBuf), "%s:%d", lp->getIpAddr(), 
				lp->getPort());
				
			address = (MaHostAddress*) hostAddresses->lookup(addrBuf);
			if (address == 0) {
				address = new MaHostAddress(addrBuf);
				hostAddresses->insert(address);
			}
			if (host) {
				address->insertVhost(new MaVhost(host));
			} else {
				address->setNamedVhost();
			}
			lp = nextLp;
		}
		ipAddr = mprStrTok(0, " \t", &tok);
	}

	if (host) {
		if (address == 0) {
			mprError(MPR_L, MPR_USER, 
				"No valid IP address for host %s", host->getName());
			return MPR_ERR_CANT_INITIALIZE;
		}
		if (address->isNamedVhost()) {
			host->setNamedVhost();
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_SSL_MODULE
//
//	Called by Host::setSslConfig which is called by SslHandlerService::setup
//

int MaServer::setSslListeners(MaHost *host, MaSslConfig *config)
{
	MaListen	*lp, *nextLp;
	char		*ipAddr, *cp;
	int			port;

	ipAddr = mprStrdup(host->getIpAddr());
	if (mprStrCmpAnyCase(ipAddr, "_default_") == 0) {
		ipAddr = "*:*";
	}

	port = -1;
	if ((cp = strchr(ipAddr, ':')) != 0) {
		*cp++ = '\0';
		if (*cp != '*') {
			port = atoi(cp);
		}
	}

	lp = (MaListen*) listens.getFirst();
	while (lp) {
		nextLp = (MaListen*) listens.getNext(lp);
		if (port > 0 && port != lp->getPort()) {
			lp = nextLp;
			continue;
		}
		if (ipAddr[0] != '*' && strcmp(ipAddr, lp->getIpAddr()) != 0) {
			lp = nextLp;
			continue;
		}
		if (host->isSecure()) {
			if (host->isNamedVhost()) {
				mprError(MPR_L, MPR_LOG, 
					"SSL does not support named virtual hosts");
				mprFree(ipAddr);
				return MPR_ERR_CANT_INITIALIZE;
			}
			lp->setSslConfig(config);
		}
		lp = nextLp;
	}
	mprFree(ipAddr);
	return 0;
}

#endif
////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_CONFIG
//
//	FUTURE -- ideal to display this via HTML also
//

void MaServer::displayConfig()
{
	MaDir			*dp;
	MaHandler		*hanp;
	MaHost			*hp;
	MaHostAddress	*ha;
	MaListen		*lp;
	MaLocation		*loc;
	MaVhost			*vp;
	char			*ext;

	mprLog("\n%s Configuration\n", mprGetMpr()->getAppName());

	mprLog("Server Configuration:\n");
	mprLog("    Name:                %s\n", name);
	mprLog("    ServerRoot           %s\n", serverRoot);
	mprLog("    Number of hosts:     %d\n", hosts.getNumItems());
	mprLog("    User:                %s\n", http->getUser());
	mprLog("    Group:               %s\n", http->getGroup());

	mprLog("    Listening on:\n");
	lp = (MaListen*) listens.getFirst();
	while (lp) {
#if BLD_FEATURE_SSL_MODULE
		mprLog("        IP Address:  %s:%d %s\n", lp->getIpAddr(), 
			lp->getPort(), lp->isSecure() ? "(SSL)" : "");
#else
		mprLog("        IP Address:  %s:%d\n", lp->getIpAddr(),
			lp->getPort());
#endif
		lp = (MaListen*) listens.getNext(lp);
	}

	hp = (MaHost*) hosts.getFirst();
	while (hp) {
		if (hp->isVhost()) {
			if (hp->isNamedVhost()) {
				mprLog("\nNamed Virtual Host: %s\n", hp->getName());
			} else {
				mprLog("\nIP Virtual Host: %s\n", hp->getName());
			}
		} else {
			mprLog("\nMain Host: %s\n", hp->getName());
		}
		mprLog("    DocumentRoot:    %s\n", hp->getDocumentRoot());
		mprLog("    HTTP version:    1.%d\n", hp->getHttpVersion());
		mprLog("    Request timeout: %d\n", hp->getTimeout());
#if BLD_FEATURE_SSL_MODULE
		mprLog("    Secure Sockets:  %s\n", hp->isSecure() ? "enabled" : "");
#endif
#if BLD_FEATURE_KEEP_ALIVE
		mprLog("    Keep alive:      %s\n", 
			(hp->getKeepAlive() == 1 ? "on" : "off"));
		if (hp->getKeepAlive() == 1) {
			mprLog("    Max keep alive   %d\n", hp->getMaxKeepAlive());
			mprLog("    Keep timeout     %d\n", hp->getKeepAliveTimeout());
		}
#endif

		mprLog("    IP Addresses:\n");
		ha = (MaHostAddress*) hostAddresses->getFirst();
		while (ha) {
			vp = (MaVhost*) ha->vhosts.getFirst();
			while (vp) {
				if (vp->getHost() == hp) {
					if (ha->getPort() == -1) {
						mprLog("        IP:          %s:*", ha->getIpAddr());
					} else {
						mprLog("        IP:          %s:%d", ha->getIpAddr(),
							ha->getPort());
					}
					if (ha->isNamedVhost()) {
						mprLog(", NamedVirtualHost\n");
					} else {
						mprLog("\n");
					}
				}
				vp = (MaVhost*) ha->vhosts.getNext(vp);
			}
			ha = (MaHostAddress*) hostAddresses->getNext(ha);
		}

		mprLog("    Directories:\n");
		dp = (MaDir*) hp->getDirs()->getFirst();
		while (dp) {
			mprLog("        Path:        %s\n", dp->getPath());
			mprLog("                     Index: %s\n", dp->getIndex());
			dp = (MaDir*) hp->getDirs()->getNext(dp);
		}

		mprLog("    Locations/ScriptAliases:\n");
		loc = (MaLocation*) hp->getLocations()->getFirst();
		while (loc) {
			mprLog("        URI Prefix   %s\n", loc->getPrefix());
			loc = (MaLocation*) hp->getLocations()->getNext(loc);
		}

		mprLog("    Handlers:\n");
		hanp = (MaHandler*) hp->getHandlers()->getFirst();
		while (hanp) {
			ext = (char*) (hanp->getExtensions() ? hanp->getExtensions() : "");
			mprLog("        Name:        %s, extensions \"%s\"\n", 
				hanp->getName(), ext);
			hanp = (MaHandler*) hp->getHandlers()->getNext(hanp);
		}
		
		hp = (MaHost*) hosts.getNext(hp);
	}
}

#endif // BLD_FEATURE_CONFIG
////////////////////////////////////////////////////////////////////////////////
//
//	Set the Server Root directory. We convert path into an absolute path.
//	WARNING: We also change directory to the serverRoot
//

void MaServer::setServerRoot(char *path)
{
	char	dir[MPR_MAX_FNAME], *cp;

	dir[sizeof(dir) - 1] = '\0';

	if (path == 0) {
#if WIN
		//
		//	On windows, we define a default server root to be the location 
		//	holding the executable so that we can co-locate DLLs with the 
		//	executable. 
		//
		char	program[MPR_MAX_FNAME];
		GetModuleFileName(0, program, sizeof(program) - 1);
		mprGetDirName(dir, sizeof(dir), program);
		mapPathDelim(dir);
		path = dir;
#else
		getcwd(dir, sizeof(dir) - 1);
		mapPathDelim(dir);
		path = dir;
#endif

	} else if (*path != '/' && 
#if WIN
			!(path[1] == ':' && path[2] == '/')) {
#else
			1) {
#endif

		getcwd(dir, sizeof(dir) - 1);
		mapPathDelim(dir);
		cp = path;
		if (*cp == '.' && cp[1] == '/') {
			cp += 2;
		}
		if (*cp == '.' && cp[1] == '\0') {
			path = dir;

		} else {
			mprSprintf(dir, sizeof(dir), "%s/%s", dir, cp);
			path = dir;
		}
	}
	chdir(path);

	mprFree(serverRoot);
	serverRoot = mprStrdup(path);
#if WIN
	//
	//	Windows is case insensitive for file names. Always map to lower case.
	//
	mprStrLower(serverRoot);
#endif
#if BLD_FEATURE_ROMFS
	fileSystem->setRoot(serverRoot);
#endif
}

////////////////////////////////////////////////////////////////////////////////

char *MaServer::getServerRoot()
{
	return serverRoot;
}

////////////////////////////////////////////////////////////////////////////////

char *MaServer::getName()
{
	return name;
}

////////////////////////////////////////////////////////////////////////////////

int MaServer::splitValue(char **s1, char **s2, char *buf, int quotes)
{
	char	*next;

	if (getValue(s1, buf, &next, quotes) < 0 || 
		getValue(s2, next, &next, quotes) < 0) {
		return MPR_ERR_BAD_SYNTAX;
	}
	if (*s1 == 0 || *s2 == 0) {
		return MPR_ERR_BAD_SYNTAX;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaServer::getValue(char **arg, char *buf, char **nextToken, int quotes)
{
	char	*endp;

	if (buf == 0) {
		return -1;
	}
	while (isspace(*buf)) {
		buf++;
	}

	if (quotes && *buf == '\"') {
		*arg = ++buf;
		if ((endp = strchr(buf, '\"')) != 0) {
			*endp++ = '\0';
		} else {
			return MPR_ERR_BAD_SYNTAX;
		}
		while (isspace(*endp)) {
			endp++;
		}
		*nextToken = endp;
	} else {
		*arg = mprStrTok(buf, " \t\n", nextToken);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

static void acceptWrapper(void *data, MprSocket *sock, char *ipAddr, int port, 
	MprSocket *lp, int isPoolThread)
{
	MprHashTable	*addrHash;
	MaHostAddress	*address;
	MaServer		*server;
	MaRequest		*rq;
	MaHost			*host;
	char			key[MPR_MAX_IP_ADDR_PORT];

	server = (MaServer*) data;

	mprLog(3, server->tMod, "New connection from %s for %s:%d %s\n", 
		ipAddr, lp->getIpAddr(), lp->getPort(),
		lp->isSecure() ? "(secure)" : "");

	//
	//	Map the address onto a suitable host. We take the first host in the
	//	address list. Host the request initially on the first host in the 
	//	chain. If this is a vhost, the first will be the default unless 
	//	the request contains a "Host:" header which it should. If a "Host:" 
	//	header is found, the request will be reassigned to the correct 
	//	virtual host once the "Host" header is read.
	//
	addrHash = server->getHostAddresses();
	mprSprintf(key, sizeof(key), "%s:%d", lp->getIpAddr(), lp->getPort());
	address = (MaHostAddress*) addrHash->lookup(key);

	if (address == 0 || ((host = address->findHost(0)) == 0)) {
		mprError(MPR_L, MPR_LOG,
			"No host configured for request %s:%d", ipAddr, port);
		sock->dispose();
		return;
	}

	rq = new MaRequest(address, host);
	host->insertRequest(rq);

	rq->acceptEvent(data, sock, ipAddr, port, lp, isPoolThread);
}

////////////////////////////////////////////////////////////////////////////////

MaHost *MaServer::getDefaultHost()
{
	return defaultHost;
}

////////////////////////////////////////////////////////////////////////////////

MaHost *MaServer::findHost(char *name)
{
	MaHost	*hp;

	hp = (MaHost*) hosts.getFirst();
	while (hp) {
		if (strcmp(hp->getName(), name) == 0) {
			return hp;
		}
		hp = (MaHost*) hosts.getNext(hp);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if UNUSED

bool MaServer::isNamedHost(MaHost *host)
{
	HostAddress		*ha;
	HashEntry		*ep;

	ep = hostAddresses->getFirst(&index);
	while (ep) {
		ha = (MaHostAddress*) ep->getObjectValue();
		vp = (MaVhost*) ha->vhosts.getFirst();
		while (vp) {
			if (vp->getHost() == hp) {
				if (ha->isNamedVhost()) {
					return 1;
				}
			}
			vp = (MaVhost*) ha->vhosts.getNext(vp);
		}
		ep = hostAddresses->getNext(ep, &index);
	}
	return 0;
}

#endif
////////////////////////////////////////////////////////////////////////////////

MprHashTable *MaServer::getHostAddresses()
{
	return hostAddresses;
}

////////////////////////////////////////////////////////////////////////////////

void MaServer::setFileSystem(MprFileSystem *fs)
{
	fileSystem = fs;
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MaHostAddress //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaHostAddress::MaHostAddress(char *ipAddrPort) : MprHashEntry(ipAddrPort)
{
	char	addrBuf[MPR_MAX_IP_ADDR_PORT];
	char	*cp;

	mprAssert(ipAddrPort && *ipAddrPort);

	flags = 0;
	ipAddr = mprStrdup(ipAddrPort);
	if ((cp = strchr(ipAddr, ':')) != 0) {
		*cp++ = '\0';
		if (*cp == '*') {
			port = -1;
		} else {
			port = atoi(cp);
		}
	} else {
		port = 80;
	}

	//
	//	Reset the key as we want the port to always be in the key and not
	//	default to port 80
	//
	mprSprintf(addrBuf, sizeof(addrBuf), "%s:%d", ipAddr, port);
	setKey(addrBuf);
}

////////////////////////////////////////////////////////////////////////////////

MaHostAddress::~MaHostAddress()
{
	MaVhost	*vp, *nextVp;

	vp = (MaVhost*) vhosts.getFirst();
	while (vp) {
		nextVp = (MaVhost*) vhosts.getNext(vp);
		vhosts.remove(vp);
		delete vp;
		vp = nextVp;
	}
	mprFree(ipAddr);
}

////////////////////////////////////////////////////////////////////////////////
//
//	No locking. Only called at config time
//

void MaHostAddress::setNamedVhost()
{
	flags |= MPR_HTTP_IPADDR_VHOST;
}

////////////////////////////////////////////////////////////////////////////////
//
//	No locking. Only called at config time
//

bool MaHostAddress::isNamedVhost()
{
	return flags & MPR_HTTP_IPADDR_VHOST;
}

////////////////////////////////////////////////////////////////////////////////

void MaHostAddress::insertVhost(MaVhost *vhost)
{
	vhosts.insert(vhost);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Look for a host with the right ServerName 
//

MaHost *MaHostAddress::findHost(char *hostStr)
{
	MaVhost	*vp;

	vp = (MaVhost*) vhosts.getFirst();
	while (vp) {
		//	FUTURE -- need to support aliases
		if (hostStr == 0 || strcmp(hostStr, vp->host->getName()) == 0) {
			return vp->host;
		}
		vp = (MaVhost*) vhosts.getNext(vp);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaHostAddress::getPort()
{
	return port;
}

////////////////////////////////////////////////////////////////////////////////

char *MaHostAddress::getIpAddr()
{
	return ipAddr;
}
////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaVhost ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaVhost::MaVhost(MaHost *hp)
{
	host = hp;
}

////////////////////////////////////////////////////////////////////////////////

MaVhost::~MaVhost()
{
}

////////////////////////////////////////////////////////////////////////////////

MaHost *MaVhost::getHost()
{
	return host;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaListen ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaListen::MaListen(char *ipName, int portNum)
{
	struct hostent	*hostent;
	char			ipBuf[MPR_MAX_IP_ADDR];

	mprAssert(ipName && *ipName);
	mprAssert(portNum > 0);

	port = portNum;
	if (!isdigit(*ipName)) {
		hostent = mprGetHostByName(ipName);
	} else {
		hostent = 0;
	}
	if (hostent) {
		mprInetNtoa(ipBuf, sizeof(ipBuf), 
			*((struct in_addr*) hostent->h_addr_list[0]));
		ipAddr = mprStrdup(ipBuf);
	} else {
		ipAddr = mprStrdup(ipName);
	}
	sock = 0;

#if BLD_FEATURE_SSL_MODULE
	secure = 0;
	sslConfig = 0;
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaListen::~MaListen()
{
	mprFree(ipAddr);
	if (sock) {
		sock->dispose();
	}
}

////////////////////////////////////////////////////////////////////////////////

int MaListen::open(MaServer *sp)
{
	MaLimits	*limits;

#if BLD_FEATURE_SSL_MODULE
	if (secure && sslConfig) {
		sock = sslConfig->newSocket();
	} else
#endif
	{
		sock = new MprSocket();
	}
	if (sock->openServer(ipAddr, port, acceptWrapper, (void*) sp, 
			MPR_SOCKET_NODELAY) < 0) {
		mprError(MPR_L, MPR_USER,
				"Can't open a socket on %s, port %d", ipAddr, port);
		return MPR_ERR_CANT_OPEN;
	}
	limits = sp->http->getLimits();
	if (limits->sendBufferSize > 0) {
		sock->setBufSize(limits->sendBufferSize, -1);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaListen::close()
{
	if (sock) {
		sock->close(MPR_SHUTDOWN_READ);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_SSL_MODULE

void MaListen::setSslConfig(MaSslConfig *config)
{
	secure = 1;
	sslConfig = config;
}

#endif
////////////////////////////////////////////////////////////////////////////////

static void mapPathDelim(char *s)
{
	while (*s) {
		if (*s == '\\') {
			*s = '/';
		}
		s++;
	}
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_DLL

static int locateModule(MprFileSystem *fileSystem, MaHost *host, 
	char *pathBuf, int pathSize, char *moduleDirs, char *module)
{
	MprFileInfo		info;
	char			*tok, *path;
	char			dirs[MPR_MAX_FNAME], tryBuf[MPR_MAX_FNAME];

	//
	//	Try the given path first without using the LoadModulePath directive.
	//
	if (host->makePath(pathBuf, pathSize, module, 0) == 0) {
		mprError(MPR_L, MPR_LOG, "Path is too long");
		return MPR_ERR_BAD_SYNTAX;
	}
	if (fileSystem->stat(pathBuf, &info) == 0) {
		return 0;
	}

	//
	//	Try using the moduleDirs path if one was specified
	//
	if (moduleDirs != 0) {
		mprStrcpy(dirs, sizeof(dirs), moduleDirs);
		path = mprStrTok(dirs, " \t\n", &tok);

		while (path) {

			mprSprintf(tryBuf, sizeof(tryBuf), "%s/%s", path, 
				mprGetBaseName(module));

			if (host->makePath(pathBuf, pathSize, tryBuf, 1) != 0) {
				if (fileSystem->stat(pathBuf, &info) == 0) {
					return 0;
				}
			}
			path = mprStrTok(0, " \t\n", &tok);
		}
	}

	return MPR_ERR_CANT_ACCESS;
}
#endif

////////////////////////////////////////////////////////////////////////////////

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
