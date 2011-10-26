# This makefile makes it very simple to build
# components from within user/xxx directories.
# Each user/xxx/Makefile should include the first line:
# -include ../user.mak
#
# This will pull in all the necessary definitions such that
# the targets: all, clean, romfs, image 
# will work from those directories
#
# If you need this to work in a lower subdirectory
# (say user/xxx/yyy) you should define _reldir=../..
# or as appropriate
#
ifndef ROOTDIR
_reldir ?= ..
ROOTDIR := $(shell pwd)/$(_reldir)/..

# Set up the default target
ALL: all

.PHONY: romfs image ALL all
image:
	$(MAKEARCH) -C $(ROOTDIR)/vendors image

endif

ifndef UCLINUX_BUILD_LIB
UCLINUX_BUILD_USER=1
endif
include $(ROOTDIR)/vendors/config/common/config.arch
-include hostbuild.mak
