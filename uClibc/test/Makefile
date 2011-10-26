# Makefile for uClibc
#
# Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
#
# Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
#

top_builddir=../
include Rules.mak

ALL_SUBDIRS := $(patsubst %/Makefile,%,$(wildcard */Makefile))

DIRS := $(ALL_SUBDIRS)
ifneq ($(HAVE_SHARED)$(UCLIBC_HAS_THREADS),yy)
	DIRS := $(filter-out dlopen,$(DIRS))
endif
ifneq ($(findstring -static,$(LDFLAGS)),)
	DIRS := $(filter-out dlopen,$(DIRS))
endif
ifneq ($(UCLIBC_HAS_THREADS),y)
	DIRS := $(filter-out pthread,$(DIRS))
endif
ifneq ($(UCLIBC_HAS_FULL_RPC),y)
	DIRS := $(filter-out rpc,$(DIRS))
endif
ifneq ($(UCLIBC_HAS_REGEX),y)
	DIRS := $(filter-out regex,$(DIRS))
endif
DIRS := $(filter-out math,$(DIRS))


test check all: run

run: compile subdirs_run

compile:subdirs_compile

tags:
	ctags -R

clean: subdirs_clean

subdirs: $(patsubst %, _dir_%, $(DIRS))
subdirs_compile: $(patsubst %, _dircompile_%, $(DIRS))
subdirs_run: $(patsubst %, _dirrun_%, $(DIRS))
subdirs_clean: $(patsubst %, _dirclean_%, $(ALL_SUBDIRS))

$(patsubst %, _dir_%, $(DIRS)) : dummy
	$(Q)$(MAKE) -C $(patsubst _dir_%, %, $@)

$(patsubst %, _dirrun_%, $(DIRS)) : dummy
	$(Q)$(MAKE) -C $(patsubst _dirrun_%, %, $@) run

$(patsubst %, _dircompile_%, $(DIRS)) : dummy
	$(Q)$(MAKE) -C $(patsubst _dircompile_%, %, $@) compile

$(patsubst %, _dirclean_%, $(ALL_SUBDIRS)) : dummy
	$(Q)$(MAKE) -C $(patsubst _dirclean_%, %, $@) clean

.PHONY: all check clean dummy subdirs_compile subdirs_run subdirs subdirs_clean test run compile
