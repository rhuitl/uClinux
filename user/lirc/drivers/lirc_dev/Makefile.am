## $Id: Makefile.am,v 1.3 2001/01/05 20:25:53 columbus Exp $

## Process this file with automake to produce Makefile.in

## this is so that Automake includes the C compiling definitions, and
## includes the source files in the distribution.
EXTRA_PROGRAMS = automake_dummy
automake_dummy_SOURCES = lirc_dev.h lirc_dev.c

## there is no *just* object file support in automake.  This is close enough
module_DATA = lirc_dev.o

# where the kernel sources are located
KERNEL_LOCATION=@kerneldir@

# some magic for using linux kernel settings
# when compiling module(s)
CC           = @kernelcc@
MI_OBJS      = $(module_DATA)
EXTRA_CFLAGS = -DIRCTL_DEV_MAJOR=$(lirc_major) -DEXPORT_SYMTAB $(DEFS)

$(module_DATA): $(automake_dummy_SOURCES) $(top_srcdir)/config.h ../lirc.h
  ifndef MAKING_MODULES
	DIR=`pwd`; (cd $(KERNEL_LOCATION); make SUBDIRS=$$DIR obj-m=$(module_DATA) modules)
  endif
# the spaces above are necessary because automake otherwise will complain
# and even worse, it will delete the line

install-exec-local: mkdev
uninstall-local: rmdev

mkdev:
	test -c @devdir@/lirc || @mknod@ @devdir@/lirc c @lirc_major@ 0

rmdev:
	test -c @devdir@/lirc && $(RM) @devdir@/lirc

install-data-local:
	-@depmod@ -a

CLEANFILES = $(module_DATA) .$(module_DATA).flags *~

include $(KERNEL_LOCATION)/Rules.make
