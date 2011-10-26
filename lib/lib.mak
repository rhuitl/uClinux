# This makefile makes it very simple to build
# components from within lib/xxx directories.
# Each lib/xxx/Makefile should include the first line:
# -include ../lib.mak
#
# This will pull in all the necessary definitions such that
# the targets: all, clean, romfs, image 
# will work from those directories
#
# If you need this to work in a lower subdirectory
# (say lib/xxx/yyy) you should define _reldir=../..
# or as appropriate
#
ifndef ROOTDIR
_reldir ?= ..
ROOTDIR := $(shell pwd)/$(_reldir)/..
endif

UCLINUX_BUILD_LIB=1
include $(ROOTDIR)/vendors/config/common/config.arch
-include hostbuild.mak

