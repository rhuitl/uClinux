#
# Makefile for dumpext - Dump the symbols of objects for DLL creation
#
# Copyright (c) Mbedthis LLC, 2003-2004. All Rights Reserved.
#

COMPILE		:= *.cpp

include 	make.dep

BLD_CC		:= $(BLD_CC_FOR_BUILD)
BLD_LD		:= $(BLD_LD_FOR_BUILD)
BLD_CFLAGS	:=
BLD_IFLAGS	:=
BLD_LDFLAGS	:=

ifeq	($(BLD_OS),WIN)
compileExtra: $(BLD_TOOLS_DIR)/dumpext$(BLD_EXE)
endif

$(BLD_TOOLS_DIR)/dumpext$(BLD_EXE): dumpext$(BLD_OBJ)
	@bld --executable $(BLD_TOOLS_DIR)/dumpext$(BLD_EXE) --native \
		dumpext$(BLD_OBJ)

cleanExtra:
	@rm -f dumpext$(BLD_EXE)

projects: dumpext.dsp 

dumpext.dsp: always
	@makeProj --executable dumpext$(BLD_EXE) --sources dumpext.c \
		--postBuild postBuild.bat

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
