#
# Makefile for the OpenSSL handler
#
# Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#

COMPILE			:= *.cpp
COMPILE_SHARED	:= yes
EXPORT_OBJECTS	:= yes
MAKE_IFLAGS		= -I../.. -I../../../mpr \
				   -I$(BLD_TOP)/$(BLD_OPENSSL_DIR)/include

include 		make.dep

ifeq	($(BLD_FEATURE_OPENSSL_MODULE),1)
ifeq	($(BLD_FEATURE_OPENSSL_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/libopenSslModule$(BLD_LIB)
endif
endif

ifeq	($(BLD_FEATURE_OPENSSL_MODULE),1)
ifeq	($(BLD_OS),WIN)
	GETDLL		+= getdll
endif
endif

modules: $(MODULES) $(GETDLL) dummy

#
#	Linux will do a static link with openssl, windows will dynamic link
#
$(BLD_BIN_DIR)/libopenSslModule$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/openSslModule$(BLD_OBJ) \
		$(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/libopenSslModule \
		--rpath $(BLD_PREFIX)/bin \
		--libraryPath $(BLD_TOP)/$(BLD_OPENSSL_DIR) \
		--libs "appWeb sslModule appWeb ssl crypto" \
		--objectsDir "$(BLD_BIN_DIR)" \
		--objects "$(BLD_OBJ_DIR)/openSslModule$(BLD_OBJ)"

getdll: always
	@cp $(BLD_TOP)/$(BLD_OPENSSL_DIR)/libeay32.dll $(BLD_BIN_DIR)
	@cp $(BLD_TOP)/$(BLD_OPENSSL_DIR)/ssleay32.dll $(BLD_BIN_DIR)

projects: always
	@makeProj --shared --library libopenSslModule \
		--libraryPath $(BLD_TOP)/$(BLD_OPENSSL_DIR) \
		--libs "appWeb sslModule appWeb ssl crypto" \
		--sources "openSslModule.cpp" --headers "openSslModule.h"
	
#
#	This should be done for OpenSSL for each new application to generate 
#	new DH parameters
#
opensslParams:
	openssl dhparam -out dh512.pem -C -2 512 >openSslDh.h
	openssl dhparam -out dh1024.pem -C -2 1024 >>openSslDh.h

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
