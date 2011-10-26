#
# gui.mak
#
# Second part of make rules, included in ptlib.mak and pwlib.mak.
# Note: Do not put any targets in the file. This should defaine variables
#       only, as targets are all in common.mak
#
# Portable Windows Library
#
# Copyright (c) 1993-1998 Equivalence Pty. Ltd.
#
# The contents of this file are subject to the Mozilla Public License
# Version 1.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
# the License for the specific language governing rights and limitations
# under the License.
#
# The Original Code is Portable Windows Library.
#
# The Initial Developer of the Original Code is Equivalence Pty. Ltd.
#
# Portions are Copyright (C) 1993 Free Software Foundation, Inc.
# All Rights Reserved.
# 
# Contributor(s): ______________________________________.
#
# $Log: gui.mak,v $
# Revision 1.15  2001/06/15 00:58:00  robertj
# Allowed for empty GUI type.
#
# Revision 1.14  2000/06/26 13:20:49  robertj
# Added ability to append resources to existing file.
#
# Revision 1.13  2000/03/20 22:43:10  craigs
# Added totally new mechanism for detecting GUI
#
# Revision 1.12  2000/03/03 00:37:42  robertj
# Fixed problem for when have GUI environment variable set, always builds GUI!
#
# Revision 1.11  2000/02/24 11:02:11  craigs
# Fixed problems with PW make
#
# Revision 1.10  2000/02/04 19:33:25  craigs
# Added ability to create non-shared versions of programs
#
# Revision 1.9  2000/01/25 04:38:52  robertj
# Another fix for shared libraries
#
# Revision 1.8  2000/01/25 04:05:23  robertj
# Fixed make files for GUI systems and moved object directories to lib directory.
#
# Revision 1.7  1999/10/24 15:29:53  craigs
# Changed default GUI for Unix to Motif
#
# Revision 1.6  1999/01/16 09:56:26  robertj
# Changed some macros to more informative names.
#
# Revision 1.5  1998/12/02 02:37:06  robertj
# New directory structure.
#


include $(PWLIBDIR)/make/defaultgui.mak

ifneq (,$(GUI_TYPE))

include $(PWLIBDIR)/make/$(GUI_TYPE).mak

ifndef	GUI_SRC_NAME
GUI_SRC_NAME	= $(GUI_TYPE)
endif

GUI_INC_DIR	= $(PWLIBDIR)/include/pwlib/$(GUI_SRC_NAME)

PWLIB           = pw_$(GUI_TYPE)_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)

#
# add GUI directory to include path
#
STDCCFLAGS      += -I$(GUI_INC_DIR)

#
# add GUI library
#
LDLIBS          += -l$(PWLIB_BASE)$(LIB_TYPE) 
ifdef	GUILIB
LDLIBS          += $(GUILIB)
endif

#
#  rules for resource compilation
#
PWRC_DIR	= $(PWLIBDIR)/tools/pwrc
PWRC		= $(PWRC_DIR)/obj_$(GUI_TYPE)_$(PLATFORM_TYPE)_r/pwrc
PWRC_CMD	= $(PWRC) -g $(GUI_TYPE)

#
# if we are using a resource file, then define the required files
#
ifdef RESOURCE

RESHDR		= $(RESOURCE:prc=h)
RESCODE		= $(RESOURCE:prc=res.cxx)
RESCXX		= $(RESOURCE:prc=cxx)
RESOBJS		= $(RESCXX:.cxx=.o) $(RESCODE:.cxx=.o)
RCFLAGS		:= $(RCFLAGS) -I "$(GUI_INC_DIR);$(PWLIBDIR)/include"

#
# create list of source files containing resource file if required
#
SOURCES		:= $(RESCODE) $(RESCXX) $(SOURCES)

#
# create list of object files containing resource file if required
#
CLEAN_FILES	:= $(CLEAN_FILES) $(RESHDR) $(RESCODE) $(RESCXX) $(RESOBJS)

endif

endif

# End of gui.mak
