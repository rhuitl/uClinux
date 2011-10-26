# Makefile for tinylogin
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

PROG      := tinylogin
VERSION   := 0.80
BUILDTIME := $(shell TZ=UTC date --utc "+%Y.%m.%d-%H:%M%z")
export VERSION

# Set the following to `true' to make a debuggable build.
# Leave this set to `false' for production use.
# eg: `make DODEBUG=true'
DODEBUG = false

# If you want a static binary, turn this on.
DOSTATIC = false

# Setting this to `true' will cause tinylogin to directly use the system's
# password and group functions.  Assuming you use GNU libc, when this is
# `true', you will need to install the /etc/nsswitch.conf configuration file
# and the required libnss_* libraries. This generally makes your embedded
# system quite a bit larger... If you leave this off, tinylogin will directly
# use the /etc/password, /etc/group files (and your system will be smaller, and
# I will get fewer emails asking about how glibc NSS works.  Enabling this adds
# just 1.5k to the binary size (which is a _lot_ less then glibc NSS costs),
# Most people will want to leave this set to false.
USE_SYSTEM_PWD_GRP = true
USE_SYSTEM_SHADOW = true

# GNU libc needs libcrypt, but libc5 wants it compiled out...
LIBRARIES = $(LIBCRYPT)

# If you are running a cross compiler, you may want to set this
# to something more interesting...
#CROSS = #powerpc-linux-
#CC = $(CROSS)gcc
#STRIPTOOL = $(CROSS)strip


# To compile vs an alternative libc, you may need to use/adjust
# the following lines to meet your needs.  This is how I make
# tinylogin compile with uC-Libc...
#LIBCDIR=/home/andersen/CVS/uClibc
#GCCINCDIR = $(shell gcc -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp")
#CFLAGS+=-nostdinc -I$(LIBCDIR)/include -I$(GCCINCDIR)
#LDFLAGS+=-nostdlib
#LIBRARIES += $(LIBCDIR)/libc.a -lgcc

# Becuase Config.h is always imported as part of Tinylogin, we set it
# up so that we can use a copy of it that gets modified
CONFIG_H=config.h


#--------------------------------------------------------


# use '-Os' optimization if available, else use -O2
OPTIMIZATION = $(shell if $(CC) -Os -S -o /dev/null -xc /dev/null >/dev/null 2>&1; \
    then echo "-Os"; else echo "-O2" ; fi)

WARNINGS = -Wall

ifeq ($(DODEBUG),true)
    CFLAGS  += $(WARNINGS) -g -D_GNU_SOURCE
    LDFLAGS += -Wl,-warn-common 
    STRIP    =
else
    CFLAGS  += $(WARNINGS) $(OPTIMIZATION) -fomit-frame-pointer -D_GNU_SOURCE
    LDFLAGS += -Wl,-warn-common 
#    STRIP    = $(STRIPTOOL) --remove-section=.note --remove-section=.comment $(PROG)
    STRIP =
endif
ifeq ($(DOSTATIC),true)
    LDFLAGS += --static
    #
    #use '-ffunction-sections -fdata-sections' and '--gc-sections' (if they 
    # work) to try and strip out any unused junk.  Doesn't do much for me, 
    # but you may want to give it a shot...
    #
    #ifeq ($(shell $(CC) -ffunction-sections -fdata-sections -S \
    #	-o /dev/null -xc /dev/null 2>/dev/null && $(LD) \
    #			--gc-sections -v >/dev/null && echo 1),1)
    #	CFLAGS += -ffunction-sections -fdata-sections
    #	LDFLAGS += --gc-sections
    #endif
endif
ifndef $(PREFIX)
    PREFIX = `pwd`/_install
endif

-include applet_source_list

OBJECTS   =  tinylogin.o env.o obscure.o pwd2spwd.o setupenv.o \
	    shell.o utmp.o utility.o usage.o 
OBJECTS   += $(APPLET_SOURCES)
CFLAGS    += -DTLG_VER='"$(VERSION)"'
CFLAGS    += -DTLG_BT='"$(BUILDTIME)"'
CFLAGS    += -DCONFIG_H='"$(CONFIG_H)"'

ifneq ($(USE_SYSTEM_PWD_GRP),true)
    PWD_LIB   = pwd_grp/libpwd.a
    LIBRARIES += $(PWD_LIB)
else
    CFLAGS    += -DUSE_SYSTEM_PWD_GRP
endif

ifneq ($(USE_SYSTEM_SHADOW),true)
	OBJECTS	+= shadow.o
endif

all:
	$(MAKE) build-config
	$(MAKE) applet_source_list
	$(MAKE) $(PWD_LIB) tinylogin tinylogin.links doc

applet_source_list: tinylogin.sh $(CONFIG_H)
	(echo -n "APPLET_SOURCES := "; $(SHELL) $^) > $@

doc: docs/TinyLogin.txt docs/TinyLogin.1 docs/TinyLogin.html

docs/TinyLogin.txt: docs/tinylogin.pod
	@echo
	@echo TinyLogin Documentation
	@echo
	- pod2text docs/tinylogin.pod > docs/TinyLogin.txt

docs/TinyLogin.1: docs/tinylogin.pod
	- pod2man --center=TinyLogin --release="version $(VERSION)" docs/tinylogin.pod > docs/TinyLogin.1

docs/TinyLogin.html: docs/tinylogin.lineo.com/TinyLogin.html
	- rm -f docs/TinyLogin.html
	- ln -s tinylogin.lineo.com/TinyLogin.html docs/TinyLogin.html

docs/tinylogin.lineo.com/TinyLogin.html: docs/tinylogin.pod
	- pod2html docs/tinylogin.pod > docs/tinylogin.lineo.com/TinyLogin.html
	- rm -f pod2html*

tinylogin: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBRARIES) $(LDLIBS)
	$(STRIP)

$(PWD_LIB):
	$(MAKE) -eC pwd_grp

tinylogin.links: tinylogin.mkll $(CONFIG_H) applets.h
	- $(SHELL) $^ | sort >$@

md5.o: md5.h
sha1.o: sha1.h
adduser.o shadow.o: shadow_.h
$(OBJECTS): %.o: $(CONFIG_H) tinylogin.h  %.c Makefile

clean:
	- rm -f tinylogin tinylogin.links *~ *.o core *.elf *.gdb
	- rm -f applet_source_list
	- rm -rf _install
	- rm -f $(CONFIG_H)-
ifneq ($(CONFIG_H),Config.h)
	- rm -f $(CONFIG_H)
endif
	- $(MAKE) -C pwd_grp clean

distclean: clean
	- rm -f tinylogin

install: tinylogin tinylogin.links
	./install.sh $(PREFIX)

install-hardlinks: tinylogin tinylogin.links
	./install.sh $(PREFIX) --hardlinks

dist release: distclean doc
	cd ..;					\
	rm -rf tinylogin-$(VERSION);		\
	cp -a tinylogin tinylogin-$(VERSION);	\
						\
	find tinylogin-$(VERSION)/ -type d	\
				 -name CVS	\
				 -print		\
		| xargs rm -rf;			\
						\
	find tinylogin-$(VERSION)/ -type f	\
				 -name .cvsignore \
				 -print		\
		| xargs rm -f;			\
						\
	find tinylogin-$(VERSION)/ -type f	\
				 -name .\#*	\
				 -print		\
		| xargs rm -f;			\
						\
	tar -cvzf tinylogin-$(VERSION).tar.gz tinylogin-$(VERSION)/;

ifdef CONFIG_UCLINUX
romfs: install-romfs.sh tinylogin.links
	cp tinylogin $(ROMFSDIR)/bin/tinylogin
	chmod 4755 $(ROMFSDIR)/bin/tinylogin
	$(SHELL) $< $(ROMFSDIR)/bin/
else
romfs: install.sh tinylogin.links
	$(SHELL) $< $(ROMFSDIR)
endif

build-config $(CONFIG_H): build-config.awk
	if [ -f "$$ROMFSDIR/bin/tinylogin" ]; then \
		inode=`ls -i $$ROMFSDIR/bin/tinylogin | awk '{print $$1}'`; \
		ls -i "$$ROMFSDIR/bin" | grep "^ *$$inode" | awk '{print $$2}' | \
			sed "s:^:$$ROMFSDIR/bin/:" | env -i xargs rm -f; \
	fi
	awk -f build-config.awk Config.h > Config.temp
	if cmp -s Config.temp $(CONFIG_H)       ;       \
	then                                            \
		rm -f Config.temp               ;       \
	else                                            \
		mv -f $(CONFIG_H) $(CONFIG_H)-  ;       \
		mv -f Config.temp $(CONFIG_H)   ;       \
		rm -f applet_source_list	;	\
		make applet_source_list		;	\
	fi
