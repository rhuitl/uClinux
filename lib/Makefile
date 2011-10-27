##############################################################################
#
#	Makefile -- Master makefile for all libraries.
#

.EXPORT_ALL_VARIABLES:

all:

##############################################################################
#
# Include architecture specific build rules.
#

_reldir = .
include lib.mak

##############################################################################

dir_base = $(LIBCDIR)

ifeq ($(LIBCDIR),libc)
.PHONY:
libm: $(LIBCDIR)
dir_base += libm
lib_libm = *.a
inc_libm = *.h,.
endif

.PHONY: libcrypt_old
libcrypt_old: $(LIBCDIR)
ifeq ($(LIBCDIR),libc)
dir_base += libcrypt_old
else
dir_$(CONFIG_LIB_LIBCRYPT_OLD) += libcrypt_old
endif
lib_libcrypt_old = libcrypt_old.a
inc_libcrypt_old = *.h,.

dir_$(CONFIG_LIB_ADNS) += adns
lib_adns = src/libadns.a

dir_$(CONFIG_LIB_FLEX) += flex
lib_flex = build/*.a
inc_flex = build/FlexLexer.h,.

dir_$(CONFIG_LIB_LIBSSL)+= libssl
lib_libssl = build/*.so* build/*.a
inc_libssl = build/include/*,.

dir_$(CONFIG_LIB_LIBGMP) += libgmp
lib_libgmp = build/install/lib/*.a
inc_libgmp = build/install/include/*.h,.

dir_$(CONFIG_LIB_LIBG) += libg
lib_libg = *.a

dir_$(CONFIG_LIB_LIBPAM) += libpam
lib_libpam = build/libpam*/.libs/*.a build/libpam*/.libs/*.so
inc_libpam = */include/security/*.h,security

dir_$(CONFIG_LIB_LIBPCAP) += libpcap
lib_libpcap = *.a
inc_libpcap = \
	pcap*.h,. \
	pcap/*.h,pcap \
	net/bpf.h,net

dir_$(CONFIG_LIB_ZLIB) += zlib
lib_zlib = libz.a* libz.so*
inc_zlib = *.h,. \

dir_$(CONFIG_LIB_LIBBZ2) += libbzip2
lib_libbzip2 = libbz2.a* libbz2.so*
inc_libbzip2 = bzlib.h,.

dir_$(CONFIG_LIB_LIBATM) += libatm
lib_libatm = \
	src/lib/.libs/*.a \
	src/lib/*.so* \
	src/lib/*.a
inc_libatm = src/include/atm*.h,.

dir_$(CONFIG_LIB_LIBNET) += Libnet

dir_$(CONFIG_LIB_LIBNETOLD) += libnet
lib_libnet = *.a
inc_libnet = *.h,.

dir_$(CONFIG_LIB_LIBJPEG) += libjpeg
lib_libjpeg = *.a
inc_libjpeg = *.h,.

dir_$(CONFIG_LIB_LIBUPNP) += libupnp
lib_libupnp = upnp/bin/*.so*
inc_libupnp = upnp/inc/upnp,.

dir_$(CONFIG_LIB_EXPAT) += expat
lib_expat = *.a *.so*
inc_expat = lib/expat.h,.

dir_$(CONFIG_LIB_LIBKRB5) += libkrb5
dep_libkrb5 = termcap
lib_libkrb5 = build/lib/*.so
inc_libkrb5 = \
	build/include/com_err.h,. \
	build/include/krb5/*.h,. \
	build/include/gssapi/*.h,.

dir_$(CONFIG_LIB_CYRUSSASL) += libcyrussasl
dep_libcyrussasl = libkrb5
lib_libcyrussasl = build/lib/.libs/*.so
inc_libcyrussasl = \
	include/*.h,sasl \
	build/include/*.h,sasl \

dir_$(CONFIG_LIB_LIBLDAP) += libldap
dep_libldap = libcyrussasl
lib_libldap = \
	builddir/libraries/libldap/.libs/*.a \
	builddir/libraries/liblber/.libs/*.a
inc_libldap = \
	include/*.h,. \
	builddir/include/*.h,.

dir_$(CONFIG_LIB_TINYTCL) += tinytcl
path_tinytcl = ../user/tinytcl
lib_tinytcl = *.a* *.so*
inc_tinytcl = *.h,.

dir_$(CONFIG_LIB_LIBCCMALLOC) += libccmalloc

dir_$(CONFIG_LIB_ARES) += libares
lib_libares = build/*.a
inc_libares = ares.h,.

dir_$(CONFIG_LIB_LIBIDN) += libidn
lib_libidn = build/lib/.libs/libidn.a
inc_libidn = lib/*.h,.

dir_$(CONFIG_LIB_LIBLZO) += lzo
lib_lzo = build/src/.libs/*.a
inc_lzo = include/lzo,.

dir_$(CONFIG_LIB_LIBPCRE) += pcre
lib_pcre = builddir/.libs/*.a
inc_pcre = \
	builddir/pcre.h,. \
	pcreposix.h,.

dir_$(CONFIG_LIB_LIBLZMA) += liblzma
lib_libzlma = *.a

dir_$(CONFIG_LIB_OSIP2) += osip2
lib_osip2 = build/install/lib/*.a
inc_osip2 = build/install/include/osip*2,.

dir_$(CONFIG_LIB_LIBEFENCE) += libefence
lib_libefence = *.a

dir_$(CONFIG_LIB_TERMCAP) += termcap
lib_termcap = *.a
inc_termcap = termcap.h,.

dir_$(CONFIG_LIB_LIBSYSFS) += sysfsutils
lib_sysfsutils = build/lib/.libs/*.a
inc_sysfsutils = include/*.h,sysfs

dir_$(CONFIG_LIB_LIBNL) += libnl
lib_libnl = lib/*.a* lib/*.so* *.pc
inc_libnl = include/netlink*,.

dir_$(CONFIG_USER_TCL_LIBTCL) += tcl
path_tcl = ../user/tcl
lib_tcl = build/*.a

dir_$(CONFIG_LIB_LIBIBERTY) += libiberty
lib_libiberty = build/*.a

dir_$(CONFIG_LIB_BFD) += bfd
lib_bfd = build/*.a
inc_bfd = build/bfd.h,.

dir_$(CONFIG_LIB_POPT) += popt
lib_popt = build/.libs/*.a
inc_popt = popt.h,.

dir_$(CONFIG_LIB_LIBJUDY) += libjudy
lib_libjudy = \
	src/obj/.libs/libJudy.a \
	src/obj/.libs/libJudy.so

dir_$(CONFIG_LIB_CLASSPATH) += classpath

dir_$(CONFIG_LIB_LIBFFI) += libffi
lib_libffi = \
	install/lib/*.a \
	install/lib/*.la \
	install/lib/pkgconfig/*.pc
inc_libffi = \
	install/include/libffi,.

dir_$(CONFIG_LIB_BITVECTOR) += bitvector
lib_bitvector = *.so
inc_bitvector = *.h,.

dir_$(CONFIG_LIB_LIBPNG) += libpng
dep_libpng = zlib
lib_libpng = *.a
inc_libpng = *.h,.

dir_$(CONFIG_LIB_LIBXML2) += libxml2
lib_libxml2 = build/.libs/libxml2.so
inc_libxml2 = \
	include/libxml/*.h,libxml \
	build/include/libxml/*.h,libxml

dir_$(CONFIG_LIB_NFNETLINK) += libnfnetlink
lib_libnfnetlink = \
	build/src/.libs/*.a* \
	build/src/.libs/*.so* \
	build/libnfnetlink.pc
inc_libnfnetlink = include/libnfnetlink,.

dir_$(CONFIG_LIB_NETFILTER_LOG) += libnetfilter_log
dep_libnetfilter_log = libnfnetlink
lib_libnetfilter_log = \
	build/src/.libs/*.a* \
	build/src/.libs/*.so* \
	build/libnetfilter_log.pc
inc_libnetfilter_log = include/libnetfilter_log,.

dir_$(CONFIG_LIB_NETFILTER_CONNTRACK) += libnetfilter_conntrack
dep_libnetfilter_conntrack = libnfnetlink
lib_libnetfilter_conntrack = \
	build/src/.libs/*.a* \
	build/src/.libs/*.so* \
	build/libnetfilter_conntrack.pc
inc_libnetfilter_conntrack = include/libnetfilter_conntrack,.

dir_$(CONFIG_LIB_PWLIB) += pwlib
dep_pwlib = STLport

dir_$(CONFIG_LIB_LIBOPENH323) += libopenh323
dep_libopenh323 = pwlib

dir_$(CONFIG_LIB_LIBMICROHTTPD) += libmicrohttpd
lib_libmicrohttpd = \
	src/daemon/.libs/*.a* \
	src/daemon/.libs/*.so* \
	libmicrohttpd.pc
inc_libmicrohttpd = \
	src/include/*.h,. \
	src/include/plibc,.


#
# dir 6, 7 and 8 reserved for Makefile.local
#
-include Makefile.local

# And build libraries in the prop directory last
dir_extra += $(ROOTDIR)/prop

include Makefile.auto

##############################################################################

DIRS_y   = $(sort $(dir_base) $(dir_y) $(dir_extra))
DIRS_all = $(dir_$(n)_n) $(dir_$(n)_) $(sort $(dir_base) $(dir_y) $(dir_n) $(dir_) $(dir_extra))
DIRPATH = $(if $(path_$(1)),$(path_$(1)),$(1))

##############################################################################

# The dynamic linker library needs to be linked into lib via a different name
LD_LIB = $(ROOTDIR)/lib/uClibc/lib/ld-uClibc-0.9.29.so
LD_LIB_DEST = $(STAGEDIR)/lib/ld-linux.so.2

##############################################################################

all: base $(DIRS_y)

define dep
.PHONY: $(1)
$(1): base $(dep_$(1))
endef

$(foreach d,$(sort $(dir_y) $(dir_n) $(dir_)),$(eval $(call dep,$(d))))

.PHONY: base
base: $(dir_base)
	@ln -sf $(LD_LIB) $(LD_LIB_DEST)		

$(dir_base): baseprep

.PHONY: baseprep
baseprep:
	mkdir -p $(STAGEDIR)/lib
	$(MAKE) -j1 -C ../include || exit $$?

.PHONY: $(dir_extra)
$(dir_extra): base $(dir_y)

# the actual dir target
.PHONY: $(DIRS_y)
$(DIRS_y):
	i=$(call DIRPATH,$@); [ ! -d $$i ] || ( touch $$i/.sgbuilt_lib && $(MAKE) $(SUBDIR_SMP_BUILD) -C $$i ) || exit $$?
	@set -f; \
	for p in $(lib_$@); do \
		set +f; \
		for i in $(ROOTDIR)/lib/$(call DIRPATH,$@)/$$p; do \
			[ ! -e "$$i" ] && continue; \
			[ "`basename $$i`" = CVS ] && continue; \
			[ -L "$(STAGEDIR)/lib/`basename $$i`" ] && continue; \
			ln -s $$i $(STAGEDIR)/lib/.; \
			echo "ln -s $$i $(STAGEDIR)/lib/."; \
		done ; \
	done	
	@set -f; \
	for p in $(inc_$@); do \
		src=$(ROOTDIR)/lib/$(call DIRPATH,$@)/`expr "$$p" : '\(.*\),.*'` ; \
		dst=$(STAGEDIR)/include/`expr "$$p" : '.*,\(.*\)'` ; \
		set +f; \
		for i in $$src; do \
			[ ! -e "$$i" ] && continue; \
			[ "`basename $$i`" = CVS ] && continue; \
			[ -L "$$dst/`basename $$i`" ] && continue; \
			[ -d $$dst ] || mkdir $$dst; \
			ln -s $$i $$dst/.; \
			echo "ln -s $$i $$dst/."; \
		done ; \
	done

%_only:
	touch $(@:_only=)/.sgbuilt_lib && $(MAKE) -j$(HOST_NCPU) $(SUBDIR_SMP_BUILD) -C $(@:_only=)

%_clean:
	$(MAKE) -j1 -C $(@:_clean=) clean; rm -f $(@:_clean=)/.sgbuilt_lib; true

%_romfs:
	$(MAKE) $(SUBDIR_SMP_BUILD) -C $(@:_romfs=) romfs

##############################################################################

# Not the best place to install these symlinks, but it will do for now
romfs:
	$(ROMFSINST) -e CONFIG_USER_FLATFSD_FLATFSD -s config/passwd /etc/passwd
	$(ROMFSINST) -e CONFIG_USER_FLATFSD_FLATFSD -s config/group /etc/group
	$(ROMFSINST) -e CONFIG_USER_FLATFSD_FLATFSD -s config/mtab /etc/mtab
	$(ROMFSINST) -e CONFIG_USER_FLATFSD_FLATFSD -s config/fstab /etc/fstab
	$(ROMFSINST) -e CONFIG_USER_FLATFSD_FLATFSD -s config/hosts /etc/hosts
	$(ROMFSINST) -e CONFIG_USER_FLATFSD_FLATFSD -s config/resolv.conf /etc/resolv.conf
	$(ROMFSINST) -e CONFIG_USER_FLATFSD_FLATFSD -e CONFIG_USER_BASH_BASH -s config/profile /etc/profile
	$(ROMFSINST) -e CONFIG_USER_FLATFSD_FLATFSD -e CONFIG_USER_TINYLOGIN_SHADOWPASSWDS -s config/shadow /etc/shadow
	for i in $(foreach d,$(DIRS_y),$(call DIRPATH,$d)) ; do \
		[ ! -d $$i ] || $(MAKE) $(SUBDIR_SMP_BUILD) -C $$i romfs || exit $$? ; \
	done

##############################################################################

clean:
	-for i in $(foreach d,$(DIRS_all),$(call DIRPATH,$d)); do \
		if [ -f $$i/.sgbuilt_lib ]; then \
			$(MAKE) -C $$i clean ; \
			rm -f $$i/.sgbuilt_lib; \
		fi; \
	done

##############################################################################

prune:
	-for i in $(foreach d,$(DIRS_all),$(call DIRPATH,$d)); do \
		found=0; \
		for j in $(sort $(foreach d,$(DIRS_y),$(call DIRPATH,$d))) ; do \
			if [ $$i = $$j ]; then \
				found=1; \
			fi; \
		done; \
		if [ $$found = 0 ]; then \
			rm -fr $$i; \
		fi; \
	done

##############################################################################
