
#
# probably add some config here eventually,  rather than ssuming the
# smallest possible solution
#

CONFOPTS = \
	--disable-rrdcgi \
	--disable-perl \
	--disable-pthread \
	--disable-tcl \
	--disable-python \
	--disable-shared \
	--enable-static \
	--disable-png \
	--disable-svg \
	--disable-pdf \
	--disable-eps \
	--disable-info \
	--disable-resize \
	--disable-tune \
	--disable-restore \
	--enable-gif

ifeq ($(CONFIG_MMU),y)
FULL_MMAP = y
endif
ifneq ($(CONFIG_UCLINUX),y)
FULL_MMAP = y
endif
ifeq ($(FULL_MMAP),y)
MMAP_OVERRIDE = ac_cv_func_mmap_fixed_mapped=yes
else
MMAP_OVERRIDE =
endif
	

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	test -f config.h.in && touch config.h.in
	(cd build; $(MMAP_OVERRIDE) sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/src/rrdtool /bin/rrdtool

