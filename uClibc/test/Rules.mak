# Rules.mak for uClibc test subdirs
#
# Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
#
# Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
#

#
# Note: This does not read the top level Rules.mak file
#

top_builddir ?= ../

TESTDIR=$(top_builddir)test/

include $(top_builddir)/Rules.mak
ifndef TEST_INSTALLED_UCLIBC
ifdef UCLIBC_LDSO
ifeq (,$(findstring /,$(UCLIBC_LDSO)))
UCLIBC_LDSO := $(top_builddir)lib/$(UCLIBC_LDSO)
endif
else
UCLIBC_LDSO := $(firstword $(wildcard $(top_builddir)lib/ld*))
endif
endif
#--------------------------------------------------------
# Ensure consistent sort order, 'gcc -print-search-dirs' behavior, etc.
LC_ALL:= C
export LC_ALL

ifeq ($(strip $(TARGET_ARCH)),)
TARGET_ARCH:=$(shell $(CC) -dumpmachine | sed -e s'/-.*//' \
	-e 's/i.86/i386/' \
	-e 's/sparc.*/sparc/' \
	-e 's/arm.*/arm/g' \
	-e 's/m68k.*/m68k/' \
	-e 's/ppc/powerpc/g' \
	-e 's/v850.*/v850/g' \
	-e 's/sh[234]/sh/' \
	-e 's/mips.*/mips/' \
	-e 's/cris.*/cris/' \
	)
endif
export TARGET_ARCH


#--------------------------------------------------------
# If you are running a cross compiler, you will want to set 'CROSS'
# to something more interesting...  Target architecture is determined
# by asking the CC compiler what arch it compiles things for, so unless
# your compiler is broken, you should not need to specify TARGET_ARCH
#
# Most people will set this stuff on the command line, i.e.
#        make CROSS=mipsel-linux-
# will build uClibc for 'mipsel'.

CROSS      = $(subst ",, $(strip $(CROSS_COMPILER_PREFIX)))
CC         = $(CROSS)gcc
RM         = rm -f

# Select the compiler needed to build binaries for your development system
HOSTCC     = gcc


#--------------------------------------------------------
# A nifty macro to make testing gcc features easier
check_gcc=$(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; \
	then echo "$(1)"; else echo "$(2)"; fi)

# use '-Os' optimization if available, else use -O2, allow Config to override
# Override optimization settings when debugging
ifeq ($(DODEBUG),y)
OPTIMIZATION    = -O0
else
OPTIMIZATION   += $(call check_gcc,-Os,-O2)
endif

XWARNINGS      := $(subst ",, $(strip $(WARNINGS))) -Wstrict-prototypes
XARCH_CFLAGS   := $(subst ",, $(strip $(ARCH_CFLAGS))) $(CPU_CFLAGS)
XCOMMON_CFLAGS := -D_GNU_SOURCE -I$(top_builddir)test
CFLAGS         += $(XWARNINGS) $(OPTIMIZATION) $(XCOMMON_CFLAGS) $(XARCH_CFLAGS) -I$(top_builddir)include $(PTINC)
HOST_CFLAGS    += $(XWARNINGS) $(OPTIMIZATION) $(XCOMMON_CFLAGS)

LDFLAGS        := $(CPU_LDFLAGS)
ifeq ($(DODEBUG),y)
	CFLAGS        += -g
	HOST_CFLAGS   += -g
	LDFLAGS       += -g
	HOST_LDFLAGS  += -g
else
	LDFLAGS       += -s
	HOST_LDFLAGS  += -s
endif

ifneq ($(strip $(HAVE_SHARED)),y)
	LDFLAGS       += -static
	HOST_LDFLAGS  += -static
endif
LDFLAGS += -B$(top_builddir)lib -Wl,-rpath,$(top_builddir)lib -Wl,-rpath-link,$(top_builddir)lib
UCLIBC_LDSO_ABSPATH=$(shell pwd)
ifdef TEST_INSTALLED_UCLIBC
LDFLAGS += -Wl,-rpath,./
UCLIBC_LDSO_ABSPATH=/lib
endif

ifeq ($(findstring -static,$(LDFLAGS)),)
	LDFLAGS += -Wl,--dynamic-linker,$(UCLIBC_LDSO_ABSPATH)/$(UCLIBC_LDSO)
endif


# Filter output
MAKEFLAGS += --no-print-directory
ifneq ($(findstring s,$(MAKEFLAGS)),)
DISP := sil
Q    := @
SCAT := -@true
else
ifneq ($(V)$(VERBOSE),)
DISP := ver
Q    :=
SCAT := cat
else
DISP := pur
Q    := @
SCAT := -@true
endif
endif

banner := ---------------------------------
pur_showclean = echo "  "CLEAN $(notdir $(CURDIR))
pur_showdiff  = echo "  "TEST_DIFF $(notdir $(CURDIR))/
pur_showlink  = echo "  "TEST_LINK $(notdir $(CURDIR))/ $@
pur_showtest  = echo "  "TEST_EXEC $(notdir $(CURDIR))/ $(patsubst %.exe,%,$@)
sil_showclean =
sil_showdiff  = true
sil_showlink  = true
sil_showtest  = true
ver_showclean =
ver_showdiff  = true echo
ver_showlink  = true echo
ver_showtest  = printf "\n$(banner)\nTEST $(notdir $(PWD))/ $(patsubst %.exe,%,$@)\n$(banner)\n"
do_showclean  = $($(DISP)_showclean)
do_showdiff   = $($(DISP)_showdiff)
do_showlink   = $($(DISP)_showlink)
do_showtest   = $($(DISP)_showtest)
showclean = @$(do_showclean)
showdiff  = @$(do_showdiff)
showlink  = @$(do_showlink)
showtest  = @$(do_showtest)
