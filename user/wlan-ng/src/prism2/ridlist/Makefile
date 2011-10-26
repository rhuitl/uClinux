# src/prism2/ridlist/Makefile 
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

include ../../../config.mk

# Implicit rules to handle the separate obj dirs
OBJ_DIR=obj

$(OBJ_DIR)/%.o : ../../shared/%.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(OBJ_DIR)/%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

# Preprocessor Options
CPPFLAGS= -I../../include -I$(LINUX_SRC)/include \
		-D__LINUX_WLAN__ -D__I386__

# Source and obj and target definitions
SHSRC=	../../shared/p80211types.c \
	../../shared/p80211metamsg.c \
	../../shared/p80211metamib.c \
	../../shared/p80211meta.c 

SHOBJ=	$(OBJ_DIR)/p80211types.o \
	$(OBJ_DIR)/p80211metamsg.o \
	$(OBJ_DIR)/p80211metamib.o \
	$(OBJ_DIR)/p80211meta.o 

MKRIDLIST_SRC=	$(SHSRC) \
		mkridlist.c
MKRIDLIST_OBJ=	$(SHOBJ) \
		$(OBJ_DIR)/mkridlist.o 

MKMIBLIST_SRC=	$(SHSRC) \
		mkmiblist.c
MKMIBLIST_OBJ=	$(SHOBJ) \
		$(OBJ_DIR)/mkmiblist.o 

# Rules
all : dirs

dirs :
	mkdir -p $(OBJ_DIR)

mkridlist:	$(MKRIDLIST_OBJ) ridlist.dat
	$(CC) -o $@ $(MKRIDLIST_OBJ)
	sort -t : -k 1 ridlist.dat > ridlist-rid.sort
	./mkridlist ridlist-rid.sort ridlist-rid
	mv ridlist-rid.html ../../../doc/prism2
	mv ridlist-rid.txt ../../../doc/prism2
	sort -t : -k 5 ridlist.dat > ridlist-mib.sort
	./mkridlist ridlist-mib.sort ridlist-mib
	mv ridlist-mib.html ../../../doc/prism2
	mv ridlist-mib.txt ../../../doc/prism2

mkmiblist:	$(MKMIBLIST_OBJ) ridlist.dat
	$(CC) -o $@ $(MKMIBLIST_OBJ)

	cut -f 1,2,5 -d : ridlist.dat | sort -t : -k 3 > miblist.sort
	./mkmiblist miblist.sort miblist

install:
	echo "Nothing to do"

clean:
	rm -f .depend
	rm -f core core.* *.o .*.o *.s *.a *.sort tmp_make *~ tags
	rm -fr $(OBJ_DIR)
	rm -f mkridlist

romfs:
	echo "Nothing to do"
