-include ../user.mak

#CONFOPTS=

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_E2FSCK_E2FSCK build/e2fsck/e2fsck /bin/e2fsck
	rm -f $(ROMFSDIR)/bin/fsck.ext2
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_E2FSCK_E2FSCK -s e2fsck /bin/fsck.ext2
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_DEBUGFS_DEBUGFS build/debugfs/debugfs /bin/debugfs
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_BADBLOCKS build/misc/badblocks /bin/badblocks
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_CHATTR build/misc/chattr /bin/chattr
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_DUMPE2FS build/misc/dumpe2fs /bin/dumpe2fs
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_FSCK build/misc/fsck /bin/fsck
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_LSATTR build/misc/lsattr /bin/lsattr
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_MKE2FS build/misc/mke2fs /bin/mke2fs
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_MKE2FS -s /bin/mke2fs /bin/mkfs.ext2
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_MKLOST_FOUND build/misc/mklost+found /bin/mklost+found
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_TUNE2FS build/misc/tune2fs /bin/tune2fs
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_UUIDGEN build/misc/uuidgen /bin/uuidgen
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_E2LABEL -s /bin/tune2fs /bin/e2label
