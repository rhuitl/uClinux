#
#	Makefile for embedded javascript (ejs)
#
#	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#

#
#	Ejs may be linked into shared handlers so we must build the objects both
#	shared and static.
#
COMPILE			:= *.cpp
COMPILE_SHARED	:= yes
EXPORT_OBJECTS	:= yes
MAKE_IFLAGS		:= -I../mpr

include 	make.dep

ifeq 			($(BLD_FEATURE_TEST),1)
POST_DIRS		:= test
endif

ifeq 			($(BLD_FEATURE_STATIC),1)
	TARGETS		+= $(BLD_BIN_DIR)/libejsStatic$(BLD_ARCHIVE)
endif
ifeq 			($(BLD_FEATURE_SHARED),1)
	TARGETS		+= $(BLD_BIN_DIR)/libejs$(BLD_SHOBJ)
endif

compileExtra: $(TARGETS)

$(BLD_BIN_DIR)/libejsStatic$(BLD_ARCHIVE): $(FILES)
	@bld --static --library $(BLD_BIN_DIR)/libejsStatic \
		--objectsDir $(BLD_OBJ_DIR) --objectList files

$(BLD_BIN_DIR)/libejs$(BLD_SHOBJ): $(FILES)
	@bld --shared --library $(BLD_BIN_DIR)/libejs \
		--objectsDir $(BLD_OBJ_DIR) --objectList files --libs mpr

#
#	Create MS Visual Studio projects
#
projects: libejs.dsp

#
#	Only build static library
#
libejs.dsp: always
	@makeProj --shared --library libejs --objectList files --libs mpr \
		--sources "ejs.cpp ejsLex.cpp ejsService.cpp" --headers "ejs.h"

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
