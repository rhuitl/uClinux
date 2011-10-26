#
# Makefile for the AppWeb server 
#
# Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#

COMPILE		:= *.cpp
MAKE_IFLAGS	= -I../mpr -I../ejs -I../http -I../http/modules

include 	make.dep 

ifeq	($(BLD_FEATURE_TEST),1)
POST_DIRS	:= samples test package
else
POST_DIRS	:= package
endif

#
#	Conditional linking for packages
#
ifeq	($(BLD_FEATURE_STATIC),1)
ifeq	($(BLD_FEATURE_PHP4_MODULE),1)
COMPILE_PHP4	:= 1
endif
ifeq	($(BLD_FEATURE_PHP5_MODULE),1)
COMPILE_PHP5	:= 1
endif
ifeq	($(BLD_FEATURE_OPENSSL_MODULE),1)
COMPILE_OPENSSL	:= 1
endif
endif
ifeq	($(BLD_FEATURE_PHP4_MODULE_BUILTIN),1)
COMPILE_PHP4	:= 1
endif
ifeq	($(BLD_FEATURE_PHP5_MODULE_BUILTIN),1)
COMPILE_PHP5	:= 1
endif
ifeq	($(BLD_FEATURE_OPENSSL_MODULE_BUILTIN),1)
COMPILE_OPENSSL	:= 1
endif

ifeq	($(COMPILE_PHP4),1)
	MAKE_IFLAGS		+= -I$(BLD_TOP)/$(BLD_PHP4_DIR) \
					   -I$(BLD_TOP)/$(BLD_PHP4_DIR)/main \
				   	   -I$(BLD_TOP)/$(BLD_PHP4_DIR)/Zend \
					   -I$(BLD_TOP)/$(BLD_PHP4_DIR)/TSRM
	STATIC_LIBS		+= $(BLD_PHP4_LIBS)
	STATIC_LIBPATH 	+= $(BLD_TOP)/$(BLD_PHP4_DIR)/libs
endif
ifeq	($(COMPILE_PHP5),1)
	MAKE_IFLAGS		+= -I$(BLD_TOP)/$(BLD_PHP5_DIR) \
					   -I$(BLD_TOP)/$(BLD_PHP5_DIR)/main \
				   	   -I$(BLD_TOP)/$(BLD_PHP5_DIR)/Zend \
					   -I$(BLD_TOP)/$(BLD_PHP5_DIR)/TSRM
	STATIC_LIBS		+= $(BLD_PHP5_LIBS)
	STATIC_LIBPATH 	+= $(BLD_TOP)/$(BLD_PHP5_DIR)/libs
endif
ifeq	($(COMPILE_OPENSSL),1)
	MAKE_IFLAGS		+= -I$(BLD_TOP)/$(BLD_OPENSSL_DIR)/include
	STATIC_LIBS		+= $(BLD_OPENSSL_LIBS)
	STATIC_LIBPATH 	+= $(BLD_TOP)/$(BLD_OPENSSL_DIR)
endif

#
#	Package libraries for appWeb, winAppWeb
#
ifeq	($(BLD_FEATURE_PHP4_MODULE_BUILTIN),1)
	LIBS	+= $(BLD_PHP4_LIBS)
	LIBPATH += $(BLD_TOP)/$(BLD_PHP4_DIR)/libs
endif
ifeq	($(BLD_FEATURE_PHP5_MODULE_BUILTIN),1)
	LIBS	+= $(BLD_PHP5_LIBS)
	LIBPATH += $(BLD_TOP)/$(BLD_PHP5_DIR)/libs
endif
ifeq	($(BLD_FEATURE_OPENSSL_MODULE_BUILTIN),1)
	LIBS	+= $(BLD_OPENSSL_LIBS)
	LIBPATH += $(BLD_TOP)/$(BLD_OPENSSL_DIR)
endif

#
#	Conditional targets for Windows
#
ifeq	($(BLD_OS),WIN)
TARGETS		+= $(BLD_BIN_DIR)/appWeb$(BLD_EXE) \
			   $(BLD_BIN_DIR)/winAppWeb$(BLD_EXE)
else
TARGETS		+= $(BLD_BIN_DIR)/appWeb$(BLD_EXE)
endif

ifeq	($(BLD_FEATURE_STATIC),1)
TARGETS		+= $(BLD_BIN_DIR)/staticAppWeb$(BLD_EXE)
endif

compileExtra: $(TARGETS)

#
#	Standard appWeb program. Linked with shared libraries using dynamic
#	loading for all modules.
#
$(BLD_BIN_DIR)/appWeb$(BLD_EXE): $(BLD_BIN_DIR)/libappWeb$(BLD_LIB) $(FILES)
	@bld --executable $(BLD_BIN_DIR)/appWeb$(BLD_EXE) \
		--rpath $(BLD_PREFIX)/bin --libraryPath "$(LIBPATH)" \
		--preferShared --smartLibs "appWeb" --libs "$(LIBS)" \
		$(BLD_OBJ_DIR)/appWeb$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/romFiles$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/appWebStaticLink$(BLD_OBJ) 

#
#	Standard Windows appWeb. Standard appWeb program. Linked with shared 
#	libraries using dynamic loading for all modules.
#
$(BLD_BIN_DIR)/winAppWeb$(BLD_EXE): $(BLD_BIN_DIR)/libappWeb$(BLD_LIB) $(FILES)
	@bld --graphical --executable $(BLD_BIN_DIR)/winAppWeb$(BLD_EXE) \
		--rpath $(BLD_PREFIX)/bin --libraryPath "$(LIBPATH)" \
		--preferShared --smartLibs "appWeb" --libs "$(LIBS)" \
		--resources appWeb.rc \
		$(BLD_OBJ_DIR)/winAppWeb$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/romFiles$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/appWebStaticLink$(BLD_OBJ) shell32.lib

#
#	Simple appWeb. Linked with static libraries and statically loading all 
#	modules. FUTURE - link package libraries (SSL & PHP) statically.
#
$(BLD_BIN_DIR)/staticAppWeb$(BLD_EXE): \
		$(BLD_BIN_DIR)/libappWebStatic$(BLD_ARCHIVE) $(FILES)
	@bld --executable $(BLD_BIN_DIR)/staticAppWeb$(BLD_EXE) \
		--rpath $(BLD_PREFIX)/bin --libraryPath "$(STATIC_LIBPATH)" \
		--libs "appWebStatic $(STATIC_LIBS)" \
		$(BLD_OBJ_DIR)/appWeb$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/romFiles$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/appWebStaticAll$(BLD_OBJ)
		
#
#	Create the MS Visual Studio project
#
projects: appWeb.dsp winAppWeb.dsp

appWeb.dsp: always
	@makeProj --executable appWeb$(BLD_EXE) \
		--rpath $(BLD_PREFIX)/bin --libraryPath "$(LIBPATH)" \
		--libs "appWeb $(LIBS)" \
		--sources "appWeb.cpp romFiles.cpp appWebStaticLink.cpp" \
		--headers "appWeb.h"

winAppWeb.dsp: always
	@makeProj --graphical --executable winAppWeb$(BLD_EXE) \
		--rpath $(BLD_PREFIX)/bin --libraryPath "$(LIBPATH)" \
		--libs "appWeb $(LIBS)" \
		--resources appWeb.rc \
		--sources "winAppWeb.cpp romFiles.cpp appWebStaticLink.cpp" \
		--headers "appWeb.h" shell32.lib

run:
	LD_LIBRARY_PATH=$(BLD_BIN_DIR) $(BLD_BIN_DIR)/appWeb -r . -l stdout:2

cleanExtra:
	@rm -f appWeb$(BLD_EXE) winAppWeb$(BLD_EXE)
	@rm -f trace.txt access.log error.log leak.log rom.files
	@rm -f Debug/*.obj Release/*.obj Debug/*.pdb Release/*.pdb

rom:
	find web -print | \
	egrep -v 'CVS|\.svn|\.cvsignore|\.ignore|\.tmp|\.sav' >rom.files
	echo -e '.\nappWeb.conf\nmime.types\nusers.db\ngroups.db' >>rom.files

size:
	@echo -e "    #\n    #	Size of appWeb\n    #"
	@size appWeb | sed -e 's/^/    # /'

debug:
	kdbg ./appWeb


#
#	Some targets to help you get going with SSL (using OpenSSL)
#	All these certificates are for internal use only.
#	Use "make ServerCertReq" to generate a certificate request to send to a
#	certificate authority like Verisign
#
#	To run appWeb, you need to do:
#
#		make caCert
#		make serverCert
#
#
#	Setup a test certificate authority. Use this if you will be generating
#	multiple certificates for clients and servers and want to validate them. 
#	The browser will say it doesn't recognize this certificate, but that is ok.
#
ca:
	umask 77 ; OPENSSL_CONF=openssl.ca ; export OPENSSL_CONF ; \
	openssl req -x509 -newkey rsa -passout pass:ca -out ca.crt -outform PEM; \
	openssl rsa -passin pass:ca -in ca.key -out ca.key.pem ; \
	echo "01" >ca.serial ; \
	>ca.db

#
#	Client certificate to put in your browser. Used when doing client validation
#
clientCert:
	umask 77 ; OPENSSL_CONF=openssl.conf ; export OPENSSL_CONF ; \
	rm -f client.crt client.key client.key.pem client.req ; \
	openssl req -passout pass:client -newkey rsa:1024 -keyout client.key \
		-out client.req < response.client ; \
	openssl rsa -passin pass:client -in client.key -out client.key.pem ; \
	OPENSSL_CONF=openssl.ca ; export OPENSSL_CONF ; \
	openssl ca -in client.req -out client.crt

#
#	Server certificate to put in AppWeb. Necessary.
#
serverCert:
	umask 77 ; OPENSSL_CONF=openssl.conf ; export OPENSSL_CONF ; \
	rm -f server.crt server.key server.key.pem server.req ; \
	openssl req -passout pass:server -newkey rsa:1024 -keyout server.key \
		-out server.req < response.server ; \
	openssl rsa -passin pass:server -in server.key -out server.key.pem ; \
	OPENSSL_CONF=openssl.ca ; export OPENSSL_CONF ; \
	openssl ca -in server.req -out server.crt

#
#	Server certificate to put in AppWeb. Necessary.
#	Use a self-signed certificate when you just want quick and dirty testing.
#	The browser will say it doesn't recognize this certificate, but that is ok.
#
serverSelfSignCert:
	umask 77 ; OPENSSL_CONF=openssl.conf ; export OPENSSL_CONF ; \
	openssl genrsa -des3 -passout pass:server -out server.key 1024 ; \
	openssl req -passin pass:server -new -x509 -days 365 -key server.key \
		-out server.crt < response.server ; \
	openssl rsa -passin pass:server -in server.key -out server.key.pem

#
#	Self-signed client request
#
clientSelfSignCert:
	umask 77 ; OPENSSL_CONF=openssl.conf ; export OPENSSL_CONF ; \
	openssl genrsa -des3 -passout pass:client -out client.key 1024 ; \
	openssl req -passin pass:client -new -x509 -days 365 -key client.key \
		-out client.crt < response.client ; \
	openssl rsa -passin pass:client -in client.key -out client.key.pem

#
#	Generate a request to send to a certificate authority like Verisign
#
ServerCertReq:
	umask 77 ; \
	openssl genrsa -des3 -passout pass:server -out server.key 1024 ; \
	openssl req -new -key server.key -out server.csr

#
#	Stop the key asking for a password by decrypting it and rewriting back
#	to server.key. WARNING: this is not secure as the key is now decrypted.
#
noPassPhrase:
	openssl genrsa 1024 -out server.key
	chmod 600 server.key

#
#	Decrypt the key into server.key.pem
#
decrypted:
	openssl rsa -in server.key -out server.key.pem

curl:
	curl --trace trace.tmp --dump-header header.tmp \
		https://127.0.0.1:4443/index.html

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
