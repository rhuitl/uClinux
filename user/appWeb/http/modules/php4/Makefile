#
# Makefile for the PHP4 handler
#
# Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#

COMPILE_SHARED	:= yes
COMPILE			:= *.cpp
EXPORT_OBJECTS	:= yes
MAKE_CFLAGS		:= -DPHP4
MAKE_IFLAGS		= -I../.. -I../../../mpr \
				   -I$(BLD_TOP)/$(BLD_PHP4_DIR) \
				   -I$(BLD_TOP)/$(BLD_PHP4_DIR)/main \
				   -I$(BLD_TOP)/$(BLD_PHP4_DIR)/Zend \
				   -I$(BLD_TOP)/$(BLD_PHP4_DIR)/TSRM

include 		make.dep

ifeq	($(BLD_FEATURE_PHP4_MODULE),1)
ifeq	($(BLD_FEATURE_PHP4_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/libphp4Module$(BLD_SHOBJ)
	MODULES		+= getPhp4Dll
endif
endif

modules: $(MODULES) dummy

$(BLD_BIN_DIR)/libphp4Module$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/php4Handler$(BLD_OBJ) $(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/libphp4Module \
		--rpath $(BLD_PREFIX)/bin \
		--libraryPath "$(BLD_TOP)/$(BLD_PHP4_DIR)/libs" \
		--preferShared --smartLibs "appWeb" --libs "$(BLD_PHP4_LIBS)" \
		$(BLD_OBJ_DIR)/php4Handler$(BLD_OBJ)

getPhp4Dll: always
	@if [ $(BLD_OS) = WIN ] ; \
	then \
		cp $(BLD_TOP)/$(BLD_PHP4_DIR)/libs/php4ts.dll $(BLD_BIN_DIR) ; \
	else \
		cp $(BLD_TOP)/$(BLD_PHP4_DIR)/libs/libphp4.so $(BLD_BIN_DIR) ; \
	fi

#
#	Create the MS Visual Studio project
#
projects: always
	@makeProj --shared --library libphp4Module \
		--libraryPath "$(BLD_TOP)/$(BLD_PHP4_DIR)/libs" --libs "appWeb php4" \
		--sources "php4Handler.cpp" --headers "php4Handler.h"

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
