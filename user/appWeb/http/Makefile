#
# Makefile for the core http server 
#
# Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#

COMPILE			:= *.cpp
COMPILE_SHARED	:= yes
EXPORT_OBJECTS	:= yes
MAKE_IFLAGS		:= -I. -I../mpr -Imodules
PRE_DIRS		:= modules

include 	make.dep

ifeq			($(BLD_FEATURE_TEST),1)
	POST_DIRS	:= test utils package
else
	POST_DIRS	:= utils package
endif
#
#	Targets to build
#
ifeq 			($(BLD_FEATURE_STATIC),1)
	TARGETS		+= $(BLD_BIN_DIR)/libappWebStatic$(BLD_ARCHIVE)
endif
ifeq 			($(BLD_FEATURE_SHARED),1)
	TARGETS		+= $(BLD_BIN_DIR)/libappWeb$(BLD_SHOBJ)
endif
TARGETS			+= $(BLD_BIN_DIR)/httpClient$(BLD_EXE)

#
#	Determine which modules must be put into the appWeb library
#
ifeq	($(BLD_FEATURE_ADMIN_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/adminHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_AUTH_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/authHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_CGI_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/cgiHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_COPY_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/copyHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_EGI_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/egiHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_ESP_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/espHandler$(BLD_OBJ) \
						   $(BLD_OBJ_DIR)/espControls$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_EJS_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/ejsModule$(BLD_OBJ) \
						   $(BLD_OBJ_DIR)/ejs$(BLD_OBJ) \
						   $(BLD_OBJ_DIR)/ejsService$(BLD_OBJ) \
						   $(BLD_OBJ_DIR)/ejsLex$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_SSL_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/sslModule$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_C_API_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/capiModule$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_COMPAT_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/compatModule$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_PHP_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/phpHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_OPENSSL_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/openSslModule$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_UPLOAD_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/uploadHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_XDB_MODULE_BUILTIN),1)
	STATIC_MODULES		+= $(BLD_OBJ_DIR)/xdbModule$(BLD_OBJ)
endif

#
#	Determine which modules must be put into the appWebStatic library
#
ifeq	($(BLD_FEATURE_ADMIN_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/adminHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_AUTH_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/authHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_CGI_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/cgiHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_COPY_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/copyHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_EGI_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/egiHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_ESP_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/espHandler$(BLD_OBJ) \
				   $(BLD_OBJ_DIR)/espControls$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_EJS_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/ejsModule$(BLD_OBJ) \
				   $(BLD_OBJ_DIR)/ejs$(BLD_OBJ) \
				   $(BLD_OBJ_DIR)/ejsService$(BLD_OBJ) \
				   $(BLD_OBJ_DIR)/ejsLex$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_SSL_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/sslModule$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_C_API_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/capiModule$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_COMPAT_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/compatModule$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_PHP_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/phpHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_OPENSSL_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/openSslModule$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_UPLOAD_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/uploadHandler$(BLD_OBJ)
endif
ifeq	($(BLD_FEATURE_XDB_MODULE),1)
	OBJS		+= $(BLD_OBJ_DIR)/xdbModule$(BLD_OBJ)
endif

#
#	Build the targets in this directory first then build all the dynamically
#	loaded modules in the modules directory.
#
compileExtra: $(TARGETS)
	@echo "    cd modules ; \
		unset COMPILE_SHARED EXPORT_OBJECTS BLD_OBJ_DIR"
	@cd modules >/dev/null ; \
	unset COMPILE_SHARED EXPORT_OBJECTS BLD_OBJ_DIR ; \
	echo -e "    $(MAKE) -S $(MAKEF) modules" ; \
	$(MAKE) --no-print-directory -S $(MAKEF) modules

#
#	Always build the appWeb static library with everything whether specified 
#	in config.make as static link or not.
#
$(BLD_BIN_DIR)/libappWebStatic$(BLD_ARCHIVE): staticFiles \
	$(shell BLD_OBJ=$(BLD_OBJ) BLD_OBJ_DIR=$(BLD_OBJ_DIR) \
		eval echo `cat staticFiles`) $(OBJS)
	@bld --static --library $(BLD_BIN_DIR)/libappWebStatic \
		--objectsDir $(BLD_OBJ_DIR) --objectList staticFiles $(OBJS)

#
#	Build the appWeb shared library only if required and only with core files
#	plus static modules.
#
$(BLD_BIN_DIR)/libappWeb$(BLD_SHOBJ): sharedFiles \
	$(shell BLD_OBJ=$(BLD_OBJ) BLD_OBJ_DIR=$(BLD_OBJ_DIR) \
		eval echo `cat sharedFiles`) $(STATIC_MODULES)
	@bld --shared --soname --library $(BLD_BIN_DIR)/libappWeb \
		--objectsDir $(BLD_OBJ_DIR) --objectList sharedFiles \
		$(STATIC_MODULES)

#
#	Build the http client
#
$(BLD_BIN_DIR)/httpClient$(BLD_EXE): $(BLD_BIN_DIR)/libappWeb$(BLD_LIB) \
		$(BLD_OBJ_DIR)/httpClient$(BLD_OBJ) $(BLD_OBJ_DIR)/client$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/url$(BLD_OBJ) $(BLD_OBJ_DIR)/crypt$(BLD_OBJ)
	@bld --executable $(BLD_BIN_DIR)/httpClient$(BLD_EXE) \
		--rpath $(BLD_PREFIX)/bin \
		--preferStatic --smartLibs "mpr" \
		--objectsDir $(BLD_OBJ_DIR) \
		--objects "$(BLD_OBJ_DIR)/httpClient$(BLD_OBJ) \
			$(BLD_OBJ_DIR)/client$(BLD_OBJ) $(BLD_OBJ_DIR)/url$(BLD_OBJ) \
			$(BLD_OBJ_DIR)/crypt$(BLD_OBJ)"

cleanExtra:
	@rm -f httpClient$(BLD_EXE)
	@rm -f trace.txt access.log error.log leak.log rom.files

rom:
	find web -type f -print | grep -v CVS >rom.files
	find http.conf -type f -print >>rom.files
	httpComp rom.files >romFiles.cpp

#
#	Create the MS Visual Studio projects
#
projects: libappWeb.dsp httpClient.dsp

#
#	Build static and shared
#
libappWeb.dsp: always
	@makeProj --shared --library libappWeb --objectList sharedFiles \
		--sourceList sourceFiles --headerList headerFiles

httpClient.dsp: always
	@makeProj --executable httpClient$(BLD_EXE) --libs "mpr" \
		--sources "httpClient.cpp client.cpp url.cpp crypt.cpp" \
		--headers "client.h shared.h"

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
