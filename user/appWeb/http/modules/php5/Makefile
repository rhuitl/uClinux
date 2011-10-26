#
# Makefile for the PHP handler
#
# Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#

COMPILE_SHARED	:= yes
COMPILE			:= *.cpp
EXPORT_OBJECTS	:= yes
BLD_PHP5_DIR 	:= ../../packages/php/php-5.0.0RC2
MAKE_CFLAGS		:= -DPHP5
MAKE_IFLAGS		= -I../.. -I../../../mpr \
				   -I$(BLD_TOP)/$(BLD_PHP5_DIR) \
				   -I$(BLD_TOP)/$(BLD_PHP5_DIR)/main \
				   -I$(BLD_TOP)/$(BLD_PHP5_DIR)/Zend \
				   -I$(BLD_TOP)/$(BLD_PHP5_DIR)/TSRM

include 		make.dep

ifeq	($(BLD_FEATURE_PHP5_MODULE),1)
ifeq	($(BLD_FEATURE_PHP5_MODULE_LOADABLE),1)
	MODULES		+= $(BLD_BIN_DIR)/libphp5Module$(BLD_SHOBJ)
	MODULES		+= getPhp5Dll
endif
endif

modules: $(MODULES) dummy

$(BLD_BIN_DIR)/libphp5Module$(BLD_SHOBJ): \
		$(BLD_OBJ_DIR)/php5Handler$(BLD_OBJ) $(BLD_BIN_DIR)/libappWeb$(BLD_LIB)
	@bld --shared --library $(BLD_BIN_DIR)/libphp5Module \
		--rpath $(BLD_PREFIX)/bin \
		--libraryPath "$(BLD_TOP)/$(BLD_PHP5_DIR)/libs" \
		--preferShared --smartLibs "appWeb" --libs "$(BLD_PHP5_LIBS)" \
		$(BLD_OBJ_DIR)/php5Handler$(BLD_OBJ)

getPhp5Dll: always
	@if [ $(BLD_OS) = WIN ] ; \
	then \
		cp $(BLD_TOP)/$(BLD_PHP5_DIR)/libs/php5ts.dll $(BLD_BIN_DIR) ; \
	else \
		cp $(BLD_TOP)/$(BLD_PHP5_DIR)/libs/libphp5.so $(BLD_BIN_DIR) ; \
	fi

#
#	Create the MS Visual Studio project
#
projects: always
	@makeProj --shared --library libphp5Module \
		--libraryPath "$(BLD_TOP)/$(BLD_PHP5_DIR)/libs" --libs "appWeb php5" \
		--sources "php5Handler.cpp" --headers "php5Handler.h"

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
