#
# Makefile for genDepend -- Generate dependendencies.
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

compileExtra: $(BLD_TOOLS_DIR)/genDepend$(BLD_EXE)

$(BLD_TOOLS_DIR)/genDepend$(BLD_EXE): genDepend$(BLD_OBJ) getopt$(BLD_OBJ)
	@bld --native --executable $(BLD_TOOLS_DIR)/genDepend$(BLD_EXE) \
		getopt$(BLD_OBJ) genDepend$(BLD_OBJ)

cleanExtra:
	@rm -f genDepend$(BLD_EXE)

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
