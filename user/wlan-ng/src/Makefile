# src/Makefile
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

include ../config.mk

DIRS=p80211 prism2 shared wlanctl wland nwepgen \
	mkmeta wlancfg
ALL_DIRS=mkmeta p80211 prism2 shared wlanctl wland \
	nwepgen wlancfg

ifneq ($(wildcard *.addon),) 
DIRS+=`cat *.addon`
ALL_DIRS+=`cat *.addon`
endif

all:
	set -e; for d in $(ALL_DIRS); do $(MAKE) -C $$d ; done

clean:
	set -e; for d in $(DIRS); do $(MAKE) -C $$d clean ; done
	rm -f core core.* *.o .*.o *.s *.a .depend tmp_make *~ tags
	set -e; for i in *_obj; do if [ -d $$i ]; then rm -fr $$i; fi; done
	rm -rf .tmp_versions
	
install:
	set -e; for d in $(DIRS); do $(MAKE) -C $$d install ; done
ifdef INSTALL_DEPMOD
	/sbin/depmod -a
endif

ctags:
	ctags -R

romfs:
	set -e; for d in $(DIRS); do $(MAKE) -C $$d romfs ; done
