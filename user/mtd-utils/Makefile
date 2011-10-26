
# -*- sh -*-

HOST_CC = gcc
HOST_AR = ar
HOST_RANLIB = ranlib
HOST_CPPFLAGS += -I/usr/include -I./include
HOST_CPPFLAGS += $(ZLIBCPPFLAGS) $(LZOCPPFLAGS)
HOST_CPPFLAGS += -DCONFIG_JFFS2_ZLIB -DCONFIG_JFFS2_RTIME
HOST_CPPFLAGS += -DWITHOUT_XATTR
HOST_LDLIBS += -lz
HOST_BUILDDIR = $(CURDIR)/build
HOST_TARGETS_$(CONFIG_JFFS2_FS) += $(HOST_BUILDDIR)/mkfs.jffs2

CPPFLAGS += -I./include
CPPFLAGS += $(ZLIBCPPFLAGS) $(LZOCPPFLAGS)
CPPFLAGS += -DCONFIG_JFFS2_ZLIB -DCONFIG_JFFS2_RTIME -DCONFIG_JFFS2_LZO
CPPFLAGS += -DWITHOUT_XATTR

SUBDIRS = lib ubi-utils mkfs.ubifs

TARGETS_$(CONFIG_USER_MTDUTILS_DOCFDISK)	+= doc_fdisk
TARGETS_$(CONFIG_USER_MTDUTILS_DOC_LOADBIOS)	+= doc_loadbios
TARGETS_$(CONFIG_USER_MTDUTILS_DOC_LOADIPL)	+= doc_loadipl
TARGETS_$(CONFIG_USER_MTDUTILS_ERASE)		+= flash_erase
TARGETS_$(CONFIG_USER_MTDUTILS_LOCK)		+= flash_lock
TARGETS_$(CONFIG_USER_MTDUTILS_UNLOCK)		+= flash_unlock
TARGETS_$(CONFIG_USER_MTDUTILS_FLASH_INFO)	+= flash_info
TARGETS_$(CONFIG_USER_MTDUTILS_FLASH_OTP_INFO)	+= flash_otp_info
TARGETS_$(CONFIG_USER_MTDUTILS_FLASH_OTP_DUMP)	+= flash_otp_dump
TARGETS_$(CONFIG_USER_MTDUTILS_FLASHCP)		+= flashcp
TARGETS_$(CONFIG_USER_MTDUTILS_FTL_CHECK)	+= ftl_check
TARGETS_$(CONFIG_USER_MTDUTILS_FTL_FORMAT)	+= ftl_format
TARGETS_$(CONFIG_USER_MTDUTILS_JFFS2DUMP)	+= jffs2dump
TARGETS_$(CONFIG_USER_MTDUTILS_MKFSJFFS2)	+= mkfs.jffs2
TARGETS_$(CONFIG_USER_MTDUTILS_MTD_DEBUG)	+= mtd_debug
TARGETS_$(CONFIG_USER_MTDUTILS_NFTL_FORMAT)	+= nftl_format
TARGETS_$(CONFIG_USER_MTDUTILS_NFTLDUMP)	+= nftldump
TARGETS_$(CONFIG_USER_MTDUTILS_NANDDUMP)	+= nanddump
TARGETS_$(CONFIG_USER_MTDUTILS_NANDTEST)	+= nandtest
TARGETS_$(CONFIG_USER_MTDUTILS_NANDWRITE)	+= nandwrite
TARGETS_$(CONFIG_USER_MTDUTILS_RFDDUMP)		+= rfddump
TARGETS_$(CONFIG_USER_MTDUTILS_RFDFORMAT)	+= rfdformat
TARGETS_$(CONFIG_USER_MTDUTILS_RECV_IMAGE)	+= recv_image
TARGETS_$(CONFIG_USER_MTDUTILS_SERVE_IMAGE)	+= serve_image
TARGETS_$(CONFIG_USER_MTDUTILS_SUMTOOL)		+= sumtool

SCRIPTS = flash_eraseall

SYMLINKS =

LDLIBS = -L$(BUILDDIR)/lib -lmtd
LDDEPS = $(BUILDDIR)/lib/libmtd.a

include common.mk

# mkfs.ubifs needs -lubi which is in ubi-utils/
subdirs_mkfs.ubifs_all: subdirs_ubi-utils_all

clean::
	-rm -f $(SYMLINKS)
ifneq ($(BUILDDIR)/.git,)
ifneq ($(BUILDDIR),.)
ifneq ($(BUILDDIR),$(CURDIR))
	rm -rf $(BUILDDIR)
endif
endif
endif

$(SYMLINKS):
	ln -sf ../fs/jffs2/$@ $@

MKFS_JFFS2_OBJS = compr_rtime.o mkfs.jffs2.o compr_zlib.o compr_lzo.o \
	compr.o rbtree.o
$(BUILDDIR)/mkfs.jffs2: $(addprefix $(BUILDDIR)/,$(MKFS_JFFS2_OBJS))
LDFLAGS_mkfs.jffs2 = $(ZLIBLDFLAGS) $(LZOLDFLAGS)
LDLIBS_mkfs.jffs2  = -lz -llzo2

$(BUILDDIR)/jffs2reader: $(BUILDDIR)/jffs2reader.o
LDFLAGS_jffs2reader = $(ZLIBLDFLAGS) $(LZOLDFLAGS)
LDLIBS_jffs2reader  = -lz -llzo2

HOST_LIB_OBJS = lib/libmtd.o lib/libmtd_legacy.o lib/libcrc32.o lib/libfec.o
HOST_MKFS_JFFS2_OBJS = $(MKFS_JFFS2_OBJS) $(HOST_LIB_OBJS)
$(HOST_BUILDDIR)/mkfs.jffs2: $(addprefix $(HOST_BUILDDIR)/,$(HOST_MKFS_JFFS2_OBJS))
	$(HOST_CC) $(HOST_CFLAGS) $(HOST_LDFLAGS) $(LDFLAGS_$(notdir $@)) -g -o $@ $^ $(HOST_LDLIBS)


$(BUILDDIR)/lib/libmtd.a: subdirs_lib_all ;

install:: ${TARGETS_y} ${SCRIPTS}
	mkdir -p ${DESTDIR}/${SBINDIR}
	install -m 0755 ${TARGETS_y} ${SCRIPTS} ${DESTDIR}/${SBINDIR}/
	mkdir -p ${DESTDIR}/${MANDIR}/man1
	gzip -9c mkfs.jffs2.1 > ${DESTDIR}/${MANDIR}/man1/mkfs.jffs2.1.gz

romfs:
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASE          /bin/flash_erase
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASEALL       /bin/flash_eraseall
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_LOCK           /bin/flash_lock
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UNLOCK         /bin/flash_unlock
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FLASH_INFO     /bin/flash_info
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FLASH_OTP_INFO /bin/flash_otp_info
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FLASH_OTP_DUMP /bin/flash_otp_dump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FLASHCP        /bin/flashcp
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FTL_CHECK      /bin/ftl_check
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FTL_FORMAT     /bin/ftl_format
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_JFFS2DUMP      /bin/jffs2dump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_MKFSJFFS2      /bin/mkfs.jffs2
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_MTD_DEBUG      /bin/mtd_debug
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NFTLDUMP       /bin/nftldump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NFTL_FORMAT    /bin/nftl_format
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDDUMP       /bin/nanddump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDTEST       /bin/nandtest
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDWRITE      /bin/nandwrite
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_DOC_LOADBIOS   /bin/doc_loadbios
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_DOC_LOADIPL    /bin/doc_loadipl
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_DOCFDISK       /bin/docfdisk
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_RFDDUMP        /bin/rfddump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_RFDFORMAT      /bin/rfdformat
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_RECV_IMAGE     /bin/recv_image
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_SERVE_IMAGE    /bin/server_image
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_SUMTOOL        /bin/sumtool

