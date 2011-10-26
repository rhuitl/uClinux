#
# Makefile for utilities for the http web server 
#
# Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#

COMPILE		:= *.cpp 
MAKE_IFLAGS	:= -I.. -I../../mpr

include 	make.dep

compileExtra: $(BLD_BIN_DIR)/charGen$(BLD_EXE) \
	$(BLD_BIN_DIR)/httpComp$(BLD_EXE) $(BLD_BIN_DIR)/httpPassword$(BLD_EXE)

$(BLD_BIN_DIR)/charGen$(BLD_EXE): charGen$(BLD_OBJ)
	@bld --executable $(BLD_BIN_DIR)/charGen$(BLD_EXE) \
		--preferStatic --smartLibs "mpr" \
		--objects charGen$(BLD_OBJ)

$(BLD_BIN_DIR)/httpComp$(BLD_EXE): httpComp$(BLD_OBJ)
	@bld --executable $(BLD_BIN_DIR)/httpComp$(BLD_EXE) \
		--preferStatic --smartLibs "mpr" \
		--objects httpComp$(BLD_OBJ)

$(BLD_BIN_DIR)/httpPassword$(BLD_EXE): httpPassword$(BLD_OBJ)
	@bld --executable $(BLD_BIN_DIR)/httpPassword$(BLD_EXE) \
		--preferStatic --smartLibs "mpr" \
		--objects "httpPassword$(BLD_OBJ) $(BLD_EXP_OBJ_DIR)/crypt$(BLD_OBJ)"

cleanExtra:
	@rm -f $(BLD_BIN_DIR)/charGen$(BLD_EXE) 
	@rm -f $(BLD_BIN_DIR)/httpComp$(BLD_EXE) 
	@rm -f $(BLD_BIN_DIR)/httpPassword$(BLD_EXE)

projects: charGen.dsp httpComp.dsp httpPassword.dsp

charGen.dsp: always
	@makeProj --executable charGen$(BLD_EXE) --libs "appWeb" \
		--sources "charGen.cpp"

httpComp.dsp: always
	@makeProj --executable httpComp$(BLD_EXE) --libs "appWeb" \
		--sources "httpComp.cpp"

httpPassword.dsp: always
	@makeProj --executable httpPassword$(BLD_EXE) --libs "appWeb" \
		--sources "httpPassword.cpp"

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
