#
# build squashfs inside the dist or for the host - davidm@snapgear.com
#

CFLAGS += -Isquashfs-tools
ifdef CONFIG_SQUASHFS_CRAMFS_MAGIC
CFLAGS += -DCONFIG_SQUASHFS_CRAMFS_MAGIC=1
endif

PROGS =
ifdef CONFIG_USER_SQUASHFS_MKSQUASHFS
PROGS += mksquashfs
endif
ifdef CONFIG_USER_SQUASHFS_MKSQUASHFS7Z
PROGS += mksquashfs7z
endif

all: $(PROGS)

.PHONY:	host_build
host_build:
	make -C squashfs-tools

romfs:
	$(ROMFSINST) -e CONFIG_USER_SQUASHFS_MKSQUASHFS /bin/mksquashfs
	$(ROMFSINST) -e CONFIG_USER_SQUASHFS_MKSQUASHFS7Z /bin/mksquashfs7z

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
	make -C squashfs-tools clean

mksquashfs: mksquashfs.o read_fs.o sort.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mksquashfs.o read_fs.o sort.o \
			-lz $(LDLIBS$(LDLIBS_$@))

mksquashfs7z: mksquashfs.o read_fs.o sort.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ mksquashfs.o read_fs.o sort.o \
			-llzma -lpthread $(CXXLIBS) $(LDLIBS$(LDLIBS_$@))

mksquashfs.o: squashfs-tools/mksquashfs.c squashfs-tools/mksquashfs.h
	$(CC) $(CFLAGS) -c -o $@ squashfs-tools/mksquashfs.c

read_fs.o: squashfs-tools/read_fs.c squashfs-tools/read_fs.h
	$(CC) $(CFLAGS) -c -o $@ squashfs-tools/read_fs.c

sort.o: squashfs-tools/sort.c
	$(CC) $(CFLAGS) -c -o $@ squashfs-tools/sort.c

