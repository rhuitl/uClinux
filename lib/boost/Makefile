#URL := http://downloads.sourceforge.net/project/boost/boost/1.44.0/boost_1_44_0.tar.bz2
URL := http://downloads.sourceforge.net/project/boost/boost/1.39.0/boost_1_39_0.tar.bz2

BJAM = tools/jam/src/build/bjam
BJAMOPTS = --prefix=$(STAGEDIR)
BJAMOPTS += -j$(HOST_NCPU)
BJAMOPTS += --layout=system
BJAMOPTS += --disable-long-double
BJAMOPTS += --without-math
BJAMOPTS += --without-graph
BJAMOPTS += --without-mpi
BJAMOPTS += --without-python
BJAMOPTS += toolset=gcc
ifeq ($(CONFIG_LIB_STLPORT),y)
BJAMOPTS += stdlib=stlport
endif

BUILDTARGET := bjam
INSTALLTARGET := bjam-install
AUTOMAKE_ROMFS := boost_romfs
include $(ROOTDIR)/tools/automake.inc

USER_CONFIG = build/$($*_BUILDDIR)/tools/build/v2/user-config.jam

build/%-bjam: build/%-configured
	[ -f build/$($*_BUILDDIR)/$(BJAM) ] || (cd build/$($*_BUILDDIR)/tools/jam/src && CC=$(HOSTCC) LOCATE_TARGET=build ./build.sh)
	echo "using gcc : `$(CXX) -dumpversion` : $(CXX) : <cxxflags>\"$(CXXFLAGS) $(CPPFLAGS)\" <linkflags>\"$(LDFLAGS)\" ; " > $(USER_CONFIG)
ifeq ($(CONFIG_LIB_STLPORT),y)
	echo "using stlport : 5.2.1 : $(STL_INCDIR) ; " >> $(USER_CONFIG)
endif
	touch $@

build/%-bjam-install: build/%-bjam
	cd build/$($*_BUILDDIR) && $(BJAM) $(BJAMOPTS) install
	ln -sf boost-1_39/boost $(STAGEDIR)/include/boost

ROMFSLIB =
ROMFSLIB += serialization
ROMFSLIB += wserialization
ROMFSLIB += thread
ROMFSLIB += system
ROMFSLIB += filesystem

boost_romfs:
	(cd $(STAGEDIR)/lib; \
	for i in $(ROMFSLIB) ; do \
		$(ROMFSINST) /lib/libboost_$$i.so.1.39.0 ; \
	done)
