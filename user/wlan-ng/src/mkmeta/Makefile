# src/mkmeta/Makefile 
#
# Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
# --------------------------------------------------------------------
#
# linux-wlan
#
#   The contents of this file are subject to the Mozilla Public
#   License Version 1.1 (the "License"); you may not use this file
#   except in compliance with the License. You may obtain a copy of
#   the License at http://www.mozilla.org/MPL/
#
#   Software distributed under the License is distributed on an "AS
#   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
#   implied. See the License for the specific language governing
#   rights and limitations under the License.
#
#   Alternatively, the contents of this file may be used under the
#   terms of the GNU Public License version 2 (the "GPL"), in which
#   case the provisions of the GPL are applicable instead of the
#   above.  If you wish to allow the use of your version of this file
#   only under the terms of the GPL and not to allow others to use
#   your version of this file under the MPL, indicate your decision
#   by deleting the provisions above and replace them with the notice
#   and other provisions required by the GPL.  If you do not delete
#   the provisions above, a recipient may use your version of this
#   file under either the MPL or the GPL.
#
# --------------------------------------------------------------------
#
# Inquiries regarding the linux-wlan Open Source project can be
# made directly to:
#
# AbsoluteValue Systems Inc.
# info@linux-wlan.com
# http://www.linux-wlan.com
#
# --------------------------------------------------------------------
#
# Portions of the development of this software were funded by 
# Intersil Corporation as part of PRISM(R) chipset product development.
#
# --------------------------------------------------------------------

include ../../config.mk

CPPFLAGS= -I../include -I$(LINUX_SRC)/include \
		-D__LINUX_WLAN__

# Implicit rules to handle the separate obj dirs
OBJ_DIR=obj

$(OBJ_DIR)/%.o : ../shared/%.c
	$(HOST_CC) -c $(HOST_CFLAGS) $(CPPFLAGS) $< -o $@

$(OBJ_DIR)/%.o : %.c
	$(HOST_CC) -c $(HOST_CFLAGS) $(CPPFLAGS) $< -o $@

# Source and obj and target definitions
SHSRC=	../shared/p80211types.c \
	../shared/p80211metamsg.c \
	../shared/p80211metamib.c \
	../shared/p80211meta.c 

SHOBJ=	$(OBJ_DIR)/p80211types.o \
	$(OBJ_DIR)/p80211metamsg.o \
	$(OBJ_DIR)/p80211metamib.o \
	$(OBJ_DIR)/p80211meta.o 

MKMETADEF_SRC=	$(SHSRC) \
		mkmetadef.c
MKMETADEF_OBJ=	$(SHOBJ) \
		$(OBJ_DIR)/mkmetadef.o 
MKMETASTRUCT_SRC=	$(SHSRC) \
			mkmetastruct.c
MKMETASTRUCT_OBJ=	$(SHOBJ) \
			$(OBJ_DIR)/mkmetastruct.o 

DEP_SRC=$(MKMETADEF_SRC) $(MKMETASTRUCT_SRC)

# Rules
all : .depend dirs mkmetadef mkmetastruct

dep .depend: $(DEP_SRC) ../../config.mk
	$(HOST_CPP) -M $(CPPFLAGS) $(DEP_SRC) > .depend

dirs :
	mkdir -p $(OBJ_DIR)



mkmetadef:	$(MKMETADEF_OBJ) mkmetadefhead.txt
	$(HOST_CC) $(HOST_LDFLAGS) -o $@ $(MKMETADEF_OBJ)
	cat mkmetadefhead.txt > ../include/wlan/p80211metadef.h
	./mkmetadef >> ../include/wlan/p80211metadef.h
	echo "#endif" >> ../include/wlan/p80211metadef.h

mkmetastruct:	$(MKMETASTRUCT_OBJ) mkmetastructhead.txt
	$(HOST_CC) $(HOST_LDFLAGS) -o $@ $(MKMETASTRUCT_OBJ)
	cat mkmetastructhead.txt > ../include/wlan/p80211metastruct.h
	./mkmetastruct >> ../include/wlan/p80211metastruct.h
	echo "#endif" >> ../include/wlan/p80211metastruct.h

install:
	echo "Nothing to install"

clean:
	rm -f core core.* *.o .*.o *.s *.a .depend tmp_make *~ tags
	rm -f ../shared/*.o
	rm -fr $(OBJ_DIR)
	rm -f mkmetadef mkmetastruct
	rm -f ../include/wlan/p80211metastruct.h
	rm -f ../include/wlan/p80211metadef.h

romfs:
	@echo "Nothing to romfs install"

#
# Include a dependency file (if one exists)
#
ifneq ($(MAKECMDGOALS), clean)
ifeq (.depend,$(wildcard .depend))
include .depend
endif
endif
