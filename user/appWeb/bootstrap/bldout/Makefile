#
#	Makefile for bldout, Build output formatter. 
#
# 	This is not just to make things pretty. Consistent formatting makes it 
#	easy to spot build errors that would otherwise go undetected.
#
# 	Copyright (c) Mbedthis LLC, 2003-2004. All Rights Reserved.
#

COMPILE		:= *.cpp

include 	make.dep

BLD_CC		= $(BLD_CC_FOR_BUILD)
BLD_LD		= $(BLD_LD_FOR_BUILD)
BLD_CFLAGS	:=
BLD_IFLAGS	:=
BLD_LDFLAGS	:=

compileExtra: $(BLD_TOOLS_DIR)/bldout$(BLD_EXE)

$(BLD_TOOLS_DIR)/bldout$(BLD_EXE):  bldout$(BLD_OBJ) getopt$(BLD_OBJ)
	@bld --executable $(BLD_TOOLS_DIR)/bldout$(BLD_EXE) --native \
		bldout$(BLD_OBJ) getopt$(BLD_OBJ)

cleanExtra:
	@rm -f bldout$(BLD_EXE)

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
