#
#	make.os -- Makefile settings for LINUX 
#
#	This file expects that the per-directory Makefiles will have included
#	their make.dep files which will in-turn include config.make and this
#	file.
#
################################################################################
#
#	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#	The latest version of this code is available at http://www.mbedthis.com
#
#	This software is open source; you can redistribute it and/or modify it 
#	under the terms of the GNU General Public License as published by the 
#	Free Software Foundation; either version 2 of the License, or (at your 
#	option) any later version.
#
#	This program is distributed WITHOUT ANY WARRANTY; without even the 
#	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
#	See the GNU General Public License for more details at:
#	http://www.mbedthis.com/downloads/gplLicense.html
#	
#	This General Public License does NOT permit incorporating this software 
#	into proprietary programs. If you are unable to comply with the GPL, a 
#	commercial license for this software and support services are available
#	from Mbedthis Software at http://www.mbedthis.com
#
################################################################################
#
#	Variables used in this script come from several sources:
#
#		- config.make
#		- user makefiles
#		- make.rules
#
#	User makefiles may define:
#
#		$(DEBUG)
#		$(MAKE_CFLAGS)
#		$(MAKE_IFLAGS)
#		$(MAKE_LDFLAGS)
#		
#	config.make will define:
#
#		$(BLD_CC)
#		$(BLD_CFLAGS)
#		$(BLD_IFLAGS)
#		$(BLD_OBJ_DIR)
#		$(BLD_PIOBJ)
#
#	make.rules will define the build output formatter 
#
#		$(BLDOUT)
#
################################################################################

ifeq		($(BLD_FEATURE_MULTITHREAD),1)
	MT  	:= -D_REENTRANT
else
	MT  	:=
endif

ifeq		($(BLD_FEATURE_MULTITHREAD),1)
	THREAD_LIB	:= -lpthread
else
	THREAD_LIB	:= 
endif

ifeq		($(BLD_FEATURE_DLL),1)
	DLL_LIB	:= -ldl
else
	DLL_LIB	:= 
endif

ifeq		($(BLD_FEATURE_LIB_STDCPP),1)
	CPP_LIB:= -lminiStdc++
else
	CPP_LIB:= -lstdc++
endif

_IFLAGS		:= -I$(BLD_TOP) 

#
#	DEBUG or RELEASE build settings
#
_LD_OPT_DEBUG	:= -g
_CC_OPT_DEBUG 	:= -g -D_DEBUG
_LD_OPT_RELEASE	:= 
_CC_OPT_RELEASE	:= -Os -D_NDEBUG
_LD_DLL			:= -shared

ifeq		($(BLD_TYPE),DEBUG)
	_LD_OPT		:= $(_LD_OPT_DEBUG)
	_CC_OPT		:= $(_CC_OPT_DEBUG)
	_CFLAGS		:= -DLINUX $(MT)
	_CPPFLAGS	:= -fno-rtti -fno-exceptions
	_CFLAGS_PIC	:= -fPIC -DPIC
else
	_LD_OPT		:= $(_LD_OPT_RELEASE)
	_CC_OPT		:= $(_CC_OPT_RELEASE)
	_CFLAGS		:= -DLINUX $(MT) -fomit-frame-pointer
	_CPPFLAGS	:= -fno-rtti -fno-exceptions
	_CFLAGS_PIC	:= -fPIC -DPIC
endif

_WARNING	:= -Wall
_LDFLAGS 	:= 
_LDPATH		+= -L$(BLD_BIN_DIR) -L$(BLD_PREFIX)/bin
_SHARED_LIBS:= $(THREAD_LIB) $(DLL_LIB) $(CPP_LIB)
_STATIC_LIBS:= $(THREAD_LIB) $(DLL_LIB) $(CPP_LIB)
_NATIVE_LIBS:= $(THREAD_LIB) $(DLL_LIB)

CLEANIT		= $(FILES) *.a *.o *.lo *.tmp *.bak core *.out *.map *.sym 

.PRECIOUS: 	$(_SHARED_LIBS)

#
#	These exports defined in this file are used by the bld program
#
export 	_LD_OPT _LD_OPT_DEBUG _LD_OPT_RELEASE _LD_DLL _LDFLAGS _WARNING \
		_NATIVE_LIBS _SHARED_LIBS _STATIC_LIBS _LDPATH BLD_TOP

#
#	Transitition rules
#
.SUFFIXES: .cpp .rc .res .def .lib .so

#
#	These rules will build objects twice if COMPILE_SHARED is true. This means
#	the makefile wants to put them in a shared library.
#
$(BLD_OBJ_DIR)/%${BLD_OBJ}: %.c
	@echo
	@if [ "$(COMPILE_SHARED)" = "yes" ];\
	then \
		echo -e "    $(BLD_CC) -c $(DEBUG) $(_CC_OPT) $(_WARNING) $(MAKE_CFLAGS) $(_CFLAGS) $(_CFLAGS_PIC) $(BLD_CFLAGS) $(MAKE_IFLAGS) $(BLD_IFLAGS) $(_IFLAGS) $< -o $(BLD_OBJ_DIR)/$*$(BLD_PIOBJ)" | $(BLDOUT) ; \
		$(BLD_CC) -c $(DEBUG) $(_CC_OPT) $(_WARNING) $(MAKE_CFLAGS) $(_CFLAGS) $(_CFLAGS_PIC) $(BLD_CFLAGS) $(MAKE_IFLAGS) $(BLD_IFLAGS) $(_IFLAGS) $< -o $(BLD_OBJ_DIR)/$*$(BLD_PIOBJ) ; \
	fi
	@echo -e "    $(BLD_CC) -c $(DEBUG) $(_CC_OPT) $(_WARNING) $(MAKE_CFLAGS) $(_CFLAGS) $(BLD_CFLAGS) $(MAKE_IFLAGS) $(BLD_IFLAGS) $(_IFLAGS) $< -o $@" | $(BLDOUT)
	@$(BLD_CC) -c $(DEBUG) $(_CC_OPT) $(_WARNING) $(MAKE_CFLAGS) $(_CFLAGS) $(BLD_CFLAGS) $(MAKE_IFLAGS) $(BLD_IFLAGS) $(_IFLAGS) $< -o $@ 

$(BLD_OBJ_DIR)/%${BLD_OBJ}: %.cpp
	@echo
	@if [ "$(COMPILE_SHARED)" = "yes" ];\
	then \
		echo -e "    $(BLD_CC) -c $(DEBUG) $(_CC_OPT) $(_WARNING) $(MAKE_CFLAGS) $(_CFLAGS) $(_CPPFLAGS) $(_CFLAGS_PIC) $(BLD_CFLAGS) $(MAKE_IFLAGS) $(BLD_IFLAGS) $(_IFLAGS) $< -o $(BLD_OBJ_DIR)/$*$(BLD_PIOBJ)" | $(BLDOUT) ; \
		$(BLD_CC) -c $(DEBUG) $(_CC_OPT) $(_WARNING) $(MAKE_CFLAGS) $(_CFLAGS) $(_CPPFLAGS) $(_CFLAGS_PIC) $(BLD_CFLAGS) $(MAKE_IFLAGS) $(BLD_IFLAGS) $(_IFLAGS) $< -o $(BLD_OBJ_DIR)/$*$(BLD_PIOBJ) ; \
	fi
	@echo "    $(BLD_CC) -c $(DEBUG) $(_CC_OPT) $(_WARNING) $(MAKE_CFLAGS) $(_CFLAGS) $(_CPPFLAGS) $(BLD_CFLAGS) $(MAKE_IFLAGS) $(BLD_IFLAGS) $(_IFLAGS) $< -o $@" | $(BLDOUT)
	@$(BLD_CC) -c $(DEBUG) $(_CC_OPT) $(_WARNING) $(MAKE_CFLAGS) $(_CFLAGS) $(_CPPFLAGS) $(BLD_CFLAGS) $(MAKE_IFLAGS) $(BLD_IFLAGS) $(_IFLAGS) $< -o $@

%${BLD_CLASS}: %.java
	@echo
	@echo "    $(BLD_JAVAC) $(JDEBUG) $(JFLAGS) $<" | $(BLDOUT)
	@$(BLD_JAVAC) $(JDEBUG) $(JFLAGS) $<

%.a:
	@true

%.so:
	@true

#
#  Local variables:
#  tab-width: 4
#  c-basic-offset: 4
#  End:
#  vim600: sw=4 ts=4 fdm=marker
#  vim<600: sw=4 ts=4
#
