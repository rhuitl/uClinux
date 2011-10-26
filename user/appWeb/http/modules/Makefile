#
# Makefile for the http modules
#
# Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#

COMPILE			:= *.cpp
COMPILE_SHARED	:= yes
EXPORT_OBJECTS	:= yes
MAKE_IFLAGS		:= -I.. -I../../mpr -I../../ejs
POST_DIRS		:= openSsl php4 php5 console

ADMIN_MODULE	:= libadminModule
AUTH_MODULE		:= libauthModule
C_API_MODULE	:= libcapiModule
CGI_MODULE		:= libcgiModule
COMPAT_MODULE	:= libcompatModule
COPY_MODULE		:= libcopyModule
EGI_MODULE		:= libegiModule
EJS_MODULE		:= libejsModule
ESP_MODULE		:= libespModule
SSL_MODULE		:= libsslModule
UPLOAD_MODULE	:= libuploadModule

include 		make.dep


#
#	Order matters. Dependencies must be earlier in the list
#
ifeq	($(BLD_FEATURE_AUTH_MODULE),1)
ifeq	($(BLD_FEATURE_AUTH_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(AUTH_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_ADMIN_MODULE),1)
ifeq	($(BLD_FEATURE_ADMIN_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(ADMIN_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_CGI_MODULE),1)
ifeq	($(BLD_FEATURE_CGI_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(CGI_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_COPY_MODULE),1)
ifeq	($(BLD_FEATURE_COPY_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(COPY_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_EGI_MODULE),1)
ifeq	($(BLD_FEATURE_EGI_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(EGI_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_EJS_MODULE),1)
ifeq	($(BLD_FEATURE_EJS_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(EJS_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_ESP_MODULE),1)
ifeq	($(BLD_FEATURE_ESP_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(ESP_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_SSL_MODULE),1)
ifeq	($(BLD_FEATURE_SSL_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(SSL_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_C_API_MODULE),1)
ifeq	($(BLD_FEATURE_C_API_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(C_API_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_COMPAT_MODULE),1)
ifeq	($(BLD_FEATURE_COMPAT_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(COMPAT_MODULE)$(BLD_SHOBJ)
endif
endif
ifeq	($(BLD_FEATURE_UPLOAD_MODULE),1)
ifeq	($(BLD_FEATURE_UPLOAD_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/$(UPLOAD_MODULE)$(BLD_SHOBJ)
endif
endif

#
#	Determine which modules need to be explicitly linked with when creating
#	the test module
#
ifeq	($(BLD_FEATURE_EJS_MODULE),1)
ifeq	($(BLD_FEATURE_EJS_MODULE_BUILTIN),0)
	EJS_LIB += ejsModule
endif
endif
ifeq	($(BLD_FEATURE_ESP_MODULE),1)
ifeq	($(BLD_FEATURE_ESP_MODULE_BUILTIN),0)
	ESP_LIB	+= espModule
endif
endif
ifeq	($(BLD_FEATURE_EGI_MODULE),1)
ifeq	($(BLD_FEATURE_EGI_MODULE_BUILTIN),0)
	EGI_LIB	+= egiModule
endif
endif

#
#	This target is called manually from ../Makefile once the appWeb library is 
#	built. 
#
modules: $(MODULES) dummy
	@T=modules ; D="$(POST_DIRS)" ; $(DO_RECURSE) 

#
#	Build Modules -- Always build all modules -- even if statically linking
#
$(BLD_BIN_DIR)/$(AUTH_MODULE)$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/authHandler$(BLD_OBJ) $(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(AUTH_MODULE) \
		--preferShared --smartLibs "appWeb" $(BLD_OBJ_DIR)/authHandler$(BLD_OBJ)

$(BLD_BIN_DIR)/$(CGI_MODULE)$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/cgiHandler$(BLD_OBJ) $(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(CGI_MODULE) \
		--preferShared --smartLibs "appWeb" $(BLD_OBJ_DIR)/cgiHandler$(BLD_OBJ)

$(BLD_BIN_DIR)/$(C_API_MODULE)$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/capiModule$(BLD_OBJ) $(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(C_API_MODULE) \
		--preferShared --libs "$(EJS_LIB) $(ESP_LIB) $(EGI_LIB)" \
		--smartLibs "appWeb" $(BLD_OBJ_DIR)/capiModule$(BLD_OBJ)

$(BLD_BIN_DIR)/$(COMPAT_MODULE)$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/compatModule$(BLD_OBJ) $(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(COMPAT_MODULE) \
		--rpath $(BLD_PREFIX)/bin --preferShared \
		--smartLibs "appWeb" --libs "$(EJS_LIB) $(ESP_LIB) $(EGI_LIB)" \
		$(BLD_OBJ_DIR)/compatModule$(BLD_OBJ)

$(BLD_BIN_DIR)/$(ADMIN_MODULE)$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/adminHandler$(BLD_OBJ) $(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(ADMIN_MODULE) \
		--preferShared --smartLibs "appWeb" \
		$(BLD_OBJ_DIR)/adminHandler$(BLD_OBJ)

$(BLD_BIN_DIR)/$(EGI_MODULE)$(BLD_SHOBJ): $(BLD_OBJ_DIR)/egiHandler$(BLD_OBJ) \
		$(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(EGI_MODULE) \
		--preferShared --smartLibs "appWeb" $(BLD_OBJ_DIR)/egiHandler$(BLD_OBJ)

$(BLD_BIN_DIR)/$(EJS_MODULE)$(BLD_SHOBJ): $(BLD_OBJ_DIR)/ejsModule$(BLD_OBJ) \
		$(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(EJS_MODULE) \
		--rpath $(BLD_PREFIX)/bin --preferShared --smartLibs "appWeb" \
		$(BLD_OBJ_DIR)/ejsModule$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/ejs$(BLD_OBJ) $(BLD_OBJ_DIR)/ejsService$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/ejsLex$(BLD_OBJ)

$(BLD_BIN_DIR)/$(ESP_MODULE)$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/espHandler$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/espControls$(BLD_OBJ) \
		$(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(ESP_MODULE) \
		--rpath $(BLD_PREFIX)/bin --preferShared \
		--smartLibs "appWeb" --libs "$(EJS_LIB)" \
		$(BLD_OBJ_DIR)/espHandler$(BLD_OBJ) \
		$(BLD_OBJ_DIR)/espControls$(BLD_OBJ)

$(BLD_BIN_DIR)/$(COPY_MODULE)$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/copyHandler$(BLD_OBJ) $(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(COPY_MODULE) \
		--preferShared --smartLibs "appWeb" $(BLD_OBJ_DIR)/copyHandler$(BLD_OBJ)

$(BLD_BIN_DIR)/$(SSL_MODULE)$(BLD_SHOBJ): $(BLD_OBJ_DIR)/sslModule$(BLD_OBJ) \
		$(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(SSL_MODULE) \
		--preferShared --smartLibs "appWeb" $(BLD_OBJ_DIR)/sslModule$(BLD_OBJ)

$(BLD_BIN_DIR)/$(UPLOAD_MODULE)$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/uploadHandler$(BLD_OBJ) \
		$(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/$(UPLOAD_MODULE) \
		--preferShared --smartLibs "appWeb" \
		$(BLD_OBJ_DIR)/uploadHandler$(BLD_OBJ)

#
#	Create the MS Visual Studio project
#
projects:
	@makeProj --shared --library $(ADMIN_MODULE) \
		--libs "appWeb" --sources "adminHandler.cpp" --headers "adminHandler.h"
	@makeProj --shared --library $(AUTH_MODULE) \
		--libs "appWeb" --sources "authHandler.cpp" --headers "adminHandler.h"
	@makeProj --shared --library $(CGI_MODULE) \
		--libs "appWeb" --sources "cgiHandler.cpp" --headers "cgiHandler.h"
	@makeProj --shared --library $(C_API_MODULE) \
		--libs "appWeb ejsModule espModule egiModule" \
		--sources "capiModule.cpp" --headers "capiModule.h"
	@makeProj --shared --library $(COMPAT_MODULE) \
		--libs "appWeb ejsModule egiModule espModule appWeb" \
		--sources "compatModule.cpp" --headers "compatModule.h"
	@makeProj --shared --library $(EGI_MODULE) \
		--libs "appWeb" --sources "egiHandler.cpp" --headers "egiModule.h"
	@makeProj --shared --library $(EJS_MODULE) --libs "appWeb" \
		--objectList ejsFiles \
		--sources "ejsModule.cpp" --headers "ejsModule.h"
	@makeProj --shared --library $(ESP_MODULE) \
		--libs "appWeb ejsModule appWeb" \
		--sources "espHandler.cpp espControls.cpp" --headers "espModule.h"
	@makeProj --shared --library $(COPY_MODULE) \
		--libs "appWeb" --sources "copyHandler.cpp" --headers "copyModule.h"
	@makeProj --shared --library $(SSL_MODULE) \
		--libs "appWeb" --sources "sslModule.cpp" --headers "sslModule.h"
	@makeProj --shared --library $(UPLOAD_MODULE) \
		--libs "appWeb" --sources "uploadHandler.cpp" \
		--headers "uploadHandler.h"

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
