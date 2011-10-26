# src/wland/Makefile
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

CPPFLAGS= -I../include -D__LINUX_WLAN__

SRCS =	wland.c \
	../shared/p80211types.c \
	../shared/p80211meta.c \
	../shared/p80211metamsg.c \
	../shared/p80211metamib.c 

OBJS =	wland.o \
	../shared/p80211types.o \
	../shared/p80211meta.o \
	../shared/p80211metamsg.o \
	../shared/p80211metamib.o 


wland: $(OBJS)
	$(CC) $(LDFLAGS) -o wland $(OBJS) $(LDLIBS) $(LIBS)

install:
	mkdir -p $(TARGET_INST_EXEDIR)
	cp -f wland $(TARGET_INST_EXEDIR)/wland

clean: 
	rm -f core core.* *.o .*.o *.s *.a .depend tmp_make *~ tags
	rm -f wland
	for i in *_obj; do if [ -d $$i ]; then rm -fr $$i; fi; done

romfs:
	$(ROMFSINST) -e CONFIG_USER_WLAN_NG_WLAND /sbin/wland
