#
# Makefile for libmtd
#

SUBDIRS =

# CFLAGS += -Werror
CPPFLAGS += -I../include
LIBS = libmtd libcrc32
TARGETS_y = libmtd.a libcrc32.a

include ../common.mk

$(BUILDDIR)/libcrc32.a: $(addprefix $(BUILDDIR)/, libcrc32.o)
$(BUILDDIR)/libmtd.a: $(addprefix $(BUILDDIR)/,\
       libmtd.o libmtd_legacy.o libcrc32.o libfec.o)

clean::
	rm -f $(addsuffix .a, $(LIBS))

install::

uninstall:
