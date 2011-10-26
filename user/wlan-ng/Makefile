# Makefile
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


DIRS = src doc man etc

CTAGOPTS = --totals -I '__initdata,__exitdata,EXPORT_SYMBOL,EXPORT_SYMBOL_NOVERS'

all:
	set -e; for d in $(DIRS); do $(MAKE) -C $$d ; done

help:
	@echo "Pick one of the following targets:"
	@echo -e "\tmake auto_config\t- automated configure"
	@echo -e "\tmake default_config\t- automated configure using default config file"
	@echo -e "\tmake config\t\t- configure and check system setup"
	@echo -e "\tmake all\t\t- build modules and programs"
	@echo -e "\tmake install\t\t- install modules and programs"
	@echo -e "\tmake clean\t\t- remove old binaries and dependency files"
	@echo -e "\tmake mrproper\t\t- 'make clean' + remove config file"
	@echo -e "\tmake tags\t\t- generate tag files for source code"
	@echo " "

mrproper: clean
	rm -f config.out
	rm -f tags.linux

clean:
	#touch config.mk config.new
	set -e; for d in $(DIRS); do $(MAKE) -C $$d clean ; done
	rm -f core core.* *.o .*.o *.s *.a .depend tmp_make *~ tags 
	for i in *_obj; do if [ -d $$i ]; then rm -fr $$i; fi; done
	#rm -f config.mk config.new
	#rm -f src/include/wlan/version.h

romfs:
	set -e; for d in $(DIRS); do $(MAKE) -C $$d romfs ; done

install:
	find . -name .depend -exec rm {} \;
	set -e; for d in $(DIRS); do $(MAKE) -C $$d install ; done

auto_config config.mk:
	@touch config.mk config.new
	@rm -f config.mk config.new
	@./Configure -d

default_config:
	@touch config.mk config.new
	@rm -f config.mk config.new
	@./Configure -d ./default.config

config:
	@touch config.mk
	@./Configure

tags: tags.linux dummy
	if [ -r tags.linux ]; then cp tags.linux tags; fi 
	find . \
		-name '*.[ch]' -o \
		-name '*.mk' -o \
		-iname 'Makefile' | \
		xargs ctags -a $(CTAGOPTS)

tags.linux:
	if [ -h linux ]; then \
		find linux/include \
			-type d \( -name 'asm-*' -o -name config \) \
			-prune -o \
			-name '*.h' -print | \
			xargs ctags -a -f $@ $(CTAGOPTS) && \
		find linux/kernel linux/drivers linux/mm linux/fs \
			linux/net linux/ipc linux/lib linux/init \
			-name '*.[ch]' | \
			xargs ctags -a -f $@ $(CTAGOPTS); \
	fi

dummy:


