#
# Makefile for ubi-utils
#

KERNELHDR := ../include

# CFLAGS += -Werror
CPPFLAGS += -Iinclude -Isrc -I$(KERNELHDR)

LIBS = libubi libubigen libiniparser libscan

TARGETS_$(CONFIG_USER_MTDUTILS_UBIUPDATEVOL)	+= ubiupdatevol
TARGETS_$(CONFIG_USER_MTDUTILS_UBIMKVOL)	+= ubimkvol
TARGETS_$(CONFIG_USER_MTDUTILS_UBIRMVOL)	+= ubirmvol
TARGETS_$(CONFIG_USER_MTDUTILS_UBICRC32)	+= ubicrc32
TARGETS_$(CONFIG_USER_MTDUTILS_UBINFO)		+= ubinfo
TARGETS_$(CONFIG_USER_MTDUTILS_UBIATTACH)	+= ubiattach
TARGETS_$(CONFIG_USER_MTDUTILS_UBIDETACH)	+= ubidetach
TARGETS_$(CONFIG_USER_MTDUTILS_UBINIZE)		+= ubinize
TARGETS_$(CONFIG_USER_MTDUTILS_UBIFORMAT)	+= ubiformat
TARGETS_$(CONFIG_USER_MTDUTILS_UBIRENAME)	+= ubirename
TARGETS_$(CONFIG_USER_MTDUTILS_MTDINFO)		+= mtdinfo
TARGETS_$(CONFIG_USER_MTDUTILS_UBIRSVOL)	+= ubirsvol


VPATH = src
LDLIBS = -L$(BUILDDIR)/../lib -lmtd

include ../common.mk

# And the below is the rule to get final executable from its .o and ubiutils-common.o
$(TARGETS_y): $(addprefix $(BUILDDIR)/,\
	libubi.a ubiutils-common.o)
#	$(CC) $(CFLAGS) $(filter %.o, $^) -L. -lubi -o $@

$(BUILDDIR)/ubicrc32: $(addprefix $(BUILDDIR)/,\
	ubicrc32.o)
#	$(CC) $(CFLAGS) -o $@ $^

$(BUILDDIR)/ubinize: $(addprefix $(BUILDDIR)/,\
	ubinize.o ubiutils-common.o libiniparser.a libubigen.a)
#	$(CC) $(CFLAGS) $(filter %.o, $^) -L. -liniparser -lubigen -o $@

$(BUILDDIR)/mtdinfo: $(addprefix $(BUILDDIR)/,\
	libubigen.a ubiutils-common.o)
#	$(CC) $(CFLAGS) $(filter %.o, $^) -L. -lmtd -lubigen -o $@

$(BUILDDIR)/ubiformat: $(addprefix $(BUILDDIR)/,\
	ubiformat.o ubiutils-common.o libscan.a libubi.a libubigen.a)
#	$(CC) $(CFLAGS) $(filter %.o, $^) -L. -lmtd -lscan -lubi -lubigen -o $@

$(BUILDDIR)/libubi.a: $(BUILDDIR)/libubi.o

$(BUILDDIR)/libubigen.a: $(BUILDDIR)/libubigen.o

$(BUILDDIR)/libiniparser.a: $(addprefix $(BUILDDIR)/,\
	libiniparser.o dictionary.o)

$(BUILDDIR)/libscan.a: $(addprefix $(BUILDDIR)/,\
	libscan.o)

clean::
	rm -f $(addsuffix .a, $(LIBS))

install::
	mkdir -p ${DESTDIR}/${SBINDIR}
	install -m 0755 ${TARGETS_y} ${DESTDIR}/${SBINDIR}/

uninstall:
	for file in ${TARGETS_y}; do \
		$(RM) ${DESTDIR}/${SBINDIR}/$$file; \
	done
