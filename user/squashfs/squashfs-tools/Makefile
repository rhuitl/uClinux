
CC = gcc
CXX = g++
AR = ar
CFLAGS = -W -Wall -O2 -g

INCLUDEDIR = .
ifndef ROOTDIR
ROOTDIR = ../../..
export ROOTDIR
endif

CFLAGS := -I$(INCLUDEDIR) -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -g

ifdef CONFIG_SQUASHFS_CRAMFS_MAGIC
CFLAGS += -DCONFIG_SQUASHFS_CRAMFS_MAGIC=1
endif

all: mksquashfs mksquashfs7z unsquashfs unsquashfs7z

mksquashfs: mksquashfs.o read_fs.o sort.o
	$(CC) mksquashfs.o read_fs.o sort.o -lz -o $@

unsquashfs: unsquashfs.o sort.o
	$(CC) unsquashfs.o -lz -o $@

liblzma.a: $(ROOTDIR)/lib/liblzma/Makefile
	$(MAKE) -f $(ROOTDIR)/lib/liblzma/Makefile

mksquashfs7z: mksquashfs.o read_fs.o sort.o liblzma.a
	$(CXX) mksquashfs.o read_fs.o sort.o -L. -llzma -lpthread -o $@

unsquashfs7z: unsquashfs.o sort.o liblzma.a
	$(CXX) unsquashfs.o -L. -llzma -lpthread -o $@

mksquashfs.o: mksquashfs.c mksquashfs.h

unsquashfs.o: unsquashfs.c

read_fs.o: read_fs.c read_fs.h

sort.o: sort.c

clean:
	rm -f *.o mksquashfs mksquashfs7z liblzma.a unsquashfs7z unsquashfs
