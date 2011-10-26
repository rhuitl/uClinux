LDFLAGS += -L$(ROOTDIR)/$(LIBCDIR)/lib

STLPORT_PKG := STLport-5.2.1
$(STLPORT_PKG)_URL := http://downloads.sourceforge.net/project/stlport/STLport/STLport-5.2.1/STLport-5.2.1.tar.bz2
$(STLPORT_PKG)_NODEFCONF := 1
$(STLPORT_PKG)_CONFOPTS := \
	--prefix= \
	--target=$(CONFIGURE_HOST) \
	--with-extra-cxxflags="${CXXFLAGS} ${CPPFLAGS}" \
	--with-extra-cflags="${CFLAGS} ${CPPFLAGS}" \
	--with-extra-ldflags="${LDFLAGS}"
ifndef CONFIG_LIB_STLPORT_SHARED
$(STLPORT_PKG)_CONFOPTS += --enable-static --disable-shared
endif
MAKEVARS = ARCH=a
AUTOMAKE_y += $(STLPORT_PKG)
AUTOMAKE_ROMFS = stlport_romfs

include $(ROOTDIR)/tools/automake.inc

stlport_romfs:
	$(ROMFSINST) -e CONFIG_LIB_STLPORT_SHARED \
		lib/libstlport.so.5.2.1 /lib/libstlport.so.5.2.1; \
	$(ROMFSINST) -e CONFIG_LIB_STLPORT_SHARED -s \
		libstlport.so.5.2.1 /lib/libstlport.so.5.2; \
