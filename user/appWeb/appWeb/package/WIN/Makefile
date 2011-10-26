#
# Makefile for the Windows AppWeb release
#
# Copyright (c) Mbedthis LLC, 2003-2004. All Rights Reserved.
#

MAKE_IFLAGS	:= -I../../../mpr 

include 	make.dep 

packageExtra:
	@BLD_PREFIX=/appWeb ./makePackage "release binary dev doc samples"

compileExtra: remove$(BLD_EXE)

remove$(BLD_EXE): $(BLD_BIN_DIR)/libmprStatic$(BLD_ARCHIVE) remove${BLD_OBJ}
	@bld --graphical --executable remove$(BLD_EXE) \
		--libs "mprStatic" "remove$(BLD_OBJ)"

cleanExtra:
	@rm -fr pkgtmp input.iss .pbldtmp bin.iss src.iss make.out Output
	@rm -f remove$(BLD_EXE)

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
