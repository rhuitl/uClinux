-include ../user.mak

######################################################

VERSION = 3.0.2

######################################################

TARGETS = flatfsd
FLATFSD_OBJS = flatfsd.o newfs.o reboot.o
FLATFS_OBJS = flatfs.o flatfs1.o ops.o

# force error checking on compile
CFLAGS += -Wall -Werror -Wmissing-prototypes

# CFLAGS += -DDEBUG

# build start time in seconds
BUILD_START_STRING ?= $(shell date -R)
BUILD_START_UNIX   := $(shell date "-d$(BUILD_START_STRING)" +%s)
CFLAGS += -DBUILD_START_UNIX=$(BUILD_START_UNIX)

######################################################
#
# Erk! settings to change the way flatfsd works
#
# Explicit setting overrides autodetect
USING_FLASH_FILESYSTEM_$(CONFIG_USER_FLATFSD_USE_FLASH_FS) = y
USING_DISKLIKE_DEVICE_$(CONFIG_USER_FLATFSD_DISKLIKE) = y
USING_DISKLIKE_DEVICE_$(CONFIG_USER_FLATFSD_CONFIG_BLOBS) = y
ifdef CONFIG_USER_FLATFSD_AUTO
	ifdef CONFIG_NFTL
		ifndef CONFIG_MTD_CFI_INTELEXT
			USING_DISKLIKE_DEVICE_$(CONFIG_SH_SECUREEDGE5410) = y
		endif
	endif
	ifeq ($(USING_DISKLIKE_DEVICE_y),)
		USING_MTD_DEVICE_$(CONFIG_MTD) = y
		USING_BLKMEM_DEVICE_$(CONFIG_BLK_DEV_BLKMEM) = y
	endif
endif

ifdef CONFIG_USER_FLATFSD_COMPRESSED
	FLATFS_OBJS += flatfs3.o
	EXTRA_LIBS += -lz
endif
ifdef CONFIG_USER_FLATFSD_ENCRYPTED
	CFLAGS += -DCONFIG_USER_FLATFSD_ENCRYPTED=1
	EXTRA_LIBS += -lssl
endif

######################################################

ifdef USING_DISKLIKE_DEVICE_y
CFLAGS += -DUSING_DISKLIKE_DEVICE=1
FLATFS_OBJS += disk.o
TARGETS += flatfs
SUBSYS = disk
else
ifdef USING_MTD_DEVICE_y
CFLAGS += -DUSING_MTD_DEVICE=1
FLATFS_OBJS += mtd.o
TARGETS += flatfs
SUBSYS = mtd
else
ifdef USING_BLKMEM_DEVICE_y
CFLAGS += -DUSING_BLKMEM_DEVICE=1
FLATFS_OBJS += blkmem.o
TARGETS += flatfs
SUBSYS = blkmem
else
ifdef USING_FLASH_FILESYSTEM_y
CFLAGS += -DUSING_FLASH_FILESYSTEM=1
SUBSYS = fs
else
all:: ERROR-no-flatfsd-storage-type-defined
endif
endif
endif
endif

ifdef CONFIG_PROP_LOGD_LOGD
CFLAGS += -DLOGGING
FLATFSD_OBJS += log.o
FLATFS_OBJS += log.o
endif
ifdef CONFIG_USER_FLATFSD_HAS_RTC
CFLAGS += -DHAS_RTC
endif

CFLAGS += -DFLATFSD_VERSION='"$(VERSION)$(SUBSYS)"'

######################################################

all:: $(TARGETS)

flatfsd: $(FLATFSD_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(FLATFSD_OBJS) $(EXTRA_LIBS) $(LDLIBS)

flatfs: $(FLATFS_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(FLATFS_OBJS) $(EXTRA_LIBS) $(LDLIBS)

romfs:
	for target in $(TARGETS) ; do \
		$(ROMFSINST) /bin/$$target; \
	done

clean:
	-rm -f flatfsd flatfs *.elf *.gdb *.o

######################################################

$(FLATFSD_OBJS) $(FLATFS_OBJS): Makefile flatfs.h
reboot.o flatfsd.o: reboot.h

######################################################
