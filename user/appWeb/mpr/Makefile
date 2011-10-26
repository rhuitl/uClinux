#
#	Makefile for the Mbedthis Portable Runtime (MPR) library
#
#	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#

COMPILE			:= *.cpp
COMPILE_SHARED	:= yes
EXPORT_OBJECTS	:= yes

include 		make.dep


ifeq 			($(BLD_FEATURE_TEST),1)
POST_DIRS		:= test samples package
else
POST_DIRS		:= package
endif

ifeq 			($(BLD_UNIX),1)
PRE_DIRS		 = UNIX
else
PRE_DIRS		 = $(BLD_OS)
endif

ifeq 			($(BLD_FEATURE_STATIC),1)
	TARGETS		+= $(BLD_BIN_DIR)/libmprStatic$(BLD_ARCHIVE)
	TARGETS		+= $(BLD_BIN_DIR)/libmprTestStatic$(BLD_ARCHIVE)
endif
ifeq 			($(BLD_FEATURE_SHARED),1)
	TARGETS		+= $(BLD_BIN_DIR)/libmpr$(BLD_SHOBJ)
	TARGETS		+= $(BLD_BIN_DIR)/libmprTest$(BLD_SHOBJ)
endif
ifeq 			($(BLD_FEATURE_LIB_STDCPP),1)
	TARGETS		+= $(BLD_BIN_DIR)/libminiStdc++$(BLD_SHOBJ)
endif

compileExtra: $(TARGETS)

#
#	Build a static MPR library
#
$(BLD_BIN_DIR)/libmprStatic$(BLD_ARCHIVE): $(FILES) files \
		$(shell BLD_OBJ=$(BLD_OBJ) BLD_OBJ_DIR=$(BLD_OBJ_DIR) \
			eval echo `cat files`)
	@bld --static --library $(BLD_BIN_DIR)/libmprStatic --entry mprDllMain \
		--objectsDir $(BLD_OBJ_DIR) --objectList files --resources mpr.rc

#
#	Build a shared MPR library
#
$(BLD_BIN_DIR)/libmpr$(BLD_SHOBJ): $(FILES) files \
		$(shell BLD_OBJ=$(BLD_OBJ) BLD_OBJ_DIR=$(BLD_OBJ_DIR) \
			eval echo `cat files`)
	@bld --shared --library $(BLD_BIN_DIR)/libmpr --entry mprDllMain \
		--objectsDir $(BLD_OBJ_DIR) --objectList files --resources mpr.rc

#
#	Build the libstdc++ replacement library
#
$(BLD_BIN_DIR)/libminiStdc++$(BLD_SHOBJ): $(BLD_OBJ_DIR)/stdcpp$(BLD_OBJ)
	@bld --static --shared --library $(BLD_BIN_DIR)/libminiStdc++ \
		$(BLD_OBJ_DIR)/stdcpp$(BLD_OBJ)

#
#	Build a static MPR test library
#
$(BLD_BIN_DIR)/libmprTestStatic$(BLD_ARCHIVE): $(BLD_OBJ_DIR)/test$(BLD_OBJ) \
		$(BLD_BIN_DIR)/libmprStatic$(BLD_ARCHIVE)
	@bld --static --library $(BLD_BIN_DIR)/libmprTestStatic --libs "mpr" \
		--objectsDir $(BLD_OBJ_DIR) "$(BLD_OBJ_DIR)/test$(BLD_OBJ)"

#
#	Build a shared MPR test library
#
$(BLD_BIN_DIR)/libmprTest$(BLD_SHOBJ): $(BLD_OBJ_DIR)/test$(BLD_OBJ) \
		$(BLD_BIN_DIR)/libmpr$(BLD_SHOBJ)
	@bld --shared --library $(BLD_BIN_DIR)/libmprTest --libs "mpr" \
		--objectsDir $(BLD_OBJ_DIR) "$(BLD_OBJ_DIR)/test$(BLD_OBJ)"

#
#	Must generate dependencies in all directories so that source distributions
#	will immediately work on all O/Ss.
#
dependExtra:
	@for dir in UNIX WIN ; \
	do \
		echo "    $(MAKE) -S $(MAKEFLAGS) $(MAKECMDGOALS) -C $${dir} " ; \
		$(MAKE) --no-print-directory -S $(MAKEFLAGS) $(MAKECMDGOALS) \
			-C $${dir} ; \
	done

#
#	Generate Visual Studio Projects
#
projects: libmpr.dsp libmprTest.dsp

#
#	Only build static libraries
#
libmpr.dsp: always
	@makeProj --shared --library libmpr --entry mprDllMain \
		--objectList files --resources mpr.rc \
		--headers "mpr.h mprOs.h" --sourceList sourceFiles

libmprTest.dsp: always
	@makeProj --shared --library libmprTest --sources "test.cpp" --libs "mpr" \
		--headers "test.h mprConfig.h" 

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
