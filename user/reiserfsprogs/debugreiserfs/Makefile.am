sbin_PROGRAMS = debugreiserfs unpack

debugreiserfs_SOURCES = debugreiserfs.c pack.c
unpack_SOURCES = unpack.c debugreiserfs.h
man_MANS = debugreiserfs.8
EXTRA_DIST = $(man_MANS)

LDADD = ../lib/libmisc.a ../reiserfscore/libcore.a

INCLUDES = -I../include
