#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for Asterisk-addons
#
# Copyright (C) 1999-2006, Digium, Inc.
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

.EXPORT_ALL_VARIABLES:

.PHONY: all install depend samples clean update distclean dist-clean menuselect chan_ooh323.so format_mp3.so

# Overwite config files on "make samples"
OVERWRITE:=y

CFLAGS+=-fPIC

# If the file .asteriskaddons.makeopts is present in your home directory, you can
# include all of your favorite menuselect options so that every time you download
# a new version of Asterisk-addons, you don't have to run menuselect to set them.
# The file /etc/asteriskaddons.makeopts will also be included but can be overridden
# by the file in your home directory.

GLOBAL_MAKEOPTS=$(wildcard /etc/asteriskaddons.makeopts)
USER_MAKEOPTS=$(wildcard ~/.asteriskaddons.makeopts)

ifeq ($(strip $(foreach var,clean distclean dist-clean update,$(findstring $(var),$(MAKECMDGOALS)))),)
 ifneq ($(wildcard menuselect.makeopts),)
  include menuselect.makeopts
  include menuselect.makedeps
 endif
endif

ifeq ($(strip $(foreach var,clean distclean dist-clean update,$(findstring $(var),$(MAKECMDGOALS)))),)
 ifneq ($(wildcard makeopts),)
  include makeopts
 endif
endif

ifeq ($(OSARCH),SunOS)
  ASTETCDIR=/var/etc/asterisk
  ASTLIBDIR=/opt/asterisk/lib
else
  ASTETCDIR=$(sysconfdir)/asterisk
  ASTLIBDIR=$(libdir)/asterisk
endif
MODULES_DIR=$(ASTLIBDIR)/modules

MODS:=app_addon_sql_mysql app_saycountpl cdr_addon_mysql chan_ooh323 format_mp3 res_config_mysql

SELECTED_MODS:=$(patsubst %,%.so,$(filter-out $(MENUSELECT_ADDONS),$(MODS)))

ifeq ($(OSARCH),Darwin)
SOLINK=-dynamic -bundle -undefined suppress -force_flat_namespace
else
SOLINK=-shared -Xlinker -x
endif
ifeq ($(OSARCH),SunOS)
SOLINK=-shared -fpic -L$(CROSS_COMPILE_TARGET)/usr/local/ssl/lib
endif

__all: all
	@echo " +---- 	  Asterisk-Addons Build Complete   ----+"
	@echo " +                                             +"
	@echo " +    Addons has successfully been built .     +"
	@echo " +    If you would like to install it :        +"
	@echo " +                                             +"
	@echo " +               $(MAKE) install                  +"
	@echo " +---------------------------------------------+"

all: config.status menuselect.makeopts 
	@$(MAKE) _all

_all: depend $(SELECTED_MODS)

config.status: configure
	@CFLAGS="" ./configure
	@echo "****"
	@echo "**** The configure script was just executed, so 'make' needs to be"
	@echo "**** restarted."
	@echo "****"
	@exit 1

install: all
	for x in $(filter-out format_mp3.so chan_ooh323.so,$(SELECTED_MODS)); do $(INSTALL) -m 755 $$x $(DESTDIR)$(MODULES_DIR) ; done
	@if test "x$(findstring format_mp3.so,$(SELECTED_MODS))" != "x" ; then \
		$(MAKE) -C format_mp3 install ; \
	fi
	@if test "x$(findstring chan_ooh323.so,$(SELECTED_MODS))" != "x" ; then \
		$(MAKE) -C asterisk-ooh323c install ; \
	fi
	@echo " +---- Asterisk-Addons Installation Complete ----+"
	@echo " +                                               +"
	@echo " +    Addons has successfully been installed.    +"
	@echo " +    If you would like to install the sample    +"
	@echo " +    configuration files (overwriting any       +"
	@echo " +    existing config files), run:               +"
	@echo " +                                               +"
	@echo " +               $(MAKE) samples                    +"
	@echo " +-----------------------------------------------+"

dist-clean: distclean

distclean: clean
	@$(MAKE) -C menuselect distclean
	@if [ -f asterisk-ooh323c/Makefile ] ; then \
		$(MAKE) -C asterisk-ooh323c distclean ; \
	fi
	rm -f build_tools/menuselect-deps
	rm -f menuselect.makeopts makeopts menuselect.makedeps
	rm -f config.log config.status
	rm -rf autom4te.cache

clean:
	rm -f *.so *.o .depend
	@$(MAKE) -C format_mp3 clean
	@$(MAKE) -C menuselect clean
	@if [ -f asterisk-ooh323c/Makefile ] ; then \
		$(MAKE) -C asterisk-ooh323c clean ; \
	fi

%.o: %.c
	$(CC) -g -c $(CFLAGS) $(MYSQLCLIENT_INCLUDE) -o $@ $<

%.so : %.o
	$(CC) $(SOLINK) -o $@ $<

ifneq ($(wildcard .depend),)
include .depend
endif

CFLAGS+=$(ASTERISK_INCLUDE)

cdr_addon_mysql.so: cdr_addon_mysql.o
	$(CC) $(SOLINK) -o $@ $< $(MYSQLCLIENT_LIB)

res_config_mysql.so: res_config_mysql.o
	$(CC) $(SOLINK) -o $@ $< $(MYSQLCLIENT_LIB)

app_addon_sql_mysql.so: app_addon_sql_mysql.o
	$(CC) $(SOLINK) -o $@ $< $(MYSQLCLIENT_LIB)

chan_ooh323.so:
	@if [ ! -f asterisk-ooh323c/Makefile ] ; then \
		cd asterisk-ooh323c && ./configure ; \
	fi
	@$(MAKE) -C asterisk-ooh323c

format_mp3.so:
	@INCLUDE="$(CFLAGS)" $(MAKE) -C format_mp3 all CC="$(CC)"

depend: .depend

.depend:
	build_tools/mkdep $(CFLAGS) $(filter-out format_mp3.c chan_ooh323.c,$(SELECTED_MODS:%.so=%.c))

samples: 
	mkdir -p $(DESTDIR)$(ASTETCDIR)
	for x in configs/*.sample; do \
		if [ -f $(DESTDIR)$(ASTETCDIR)/`basename $$x .sample` ]; then \
			if [ "$(OVERWRITE)" = "y" ]; then \
				if cmp -s $(DESTDIR)$(ASTETCDIR)/`basename $$x .sample` $$x ; then \
					echo "Config file $$x is unchanged"; \
					continue; \
				fi ; \
				mv -f $(DESTDIR)$(ASTETCDIR)/`basename $$x .sample` $(DESTDIR)$(ASTETCDIR)/`basename $$x .sample`.old ; \
			else \
				echo "Skipping config file $$x"; \
				continue; \
			fi ;\
		fi ; \
		$(INSTALL) -m 644 $$x $(DESTDIR)$(ASTETCDIR)/`basename $$x .sample` ;\
	done

update:
	@if [ -d .svn ]; then \
		echo "Updating from Subversion..." ; \
		svn update -q; \
	else \
		echo "Not under version control"; \
	fi

menuselect.makeopts menuselect.makedeps: menuselect/menuselect menuselect-tree
	@menuselect/menuselect --check-deps $(GLOBAL_MAKEOPTS) $(USER_MAKEOPTS) menuselect.makeopts

menuconfig: menuselect

menuselect: menuselect/menuselect menuselect-tree
	-@menuselect/menuselect $(GLOBAL_MAKEOPTS) $(USER_MAKEOPTS) menuselect.makeopts && echo "menuselect changes saved!" || echo "menuselect changes NOT saved!"

menuselect/menuselect: menuselect/menuselect.c menuselect/menuselect_curses.c menuselect/menuselect_stub.c menuselect/menuselect.h menuselect/linkedlists.h config.status
	@CFLAGS="" $(MAKE) -C menuselect
