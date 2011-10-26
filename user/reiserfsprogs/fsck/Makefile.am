sbin_PROGRAMS = reiserfsck

reiserfsck_SOURCES = main.c pass0.c pass1.c pass2.c semantic.c pass4.c lost+found.c \
ubitmap.c uobjectid.c ustree.c ufile.c check.c check_tree.c journal.c info.c segments.c\
fsck.h
man_MANS = reiserfsck.8
EXTRA_DIST = $(man_MANS)

LDADD = ../lib/libmisc.a ../reiserfscore/libcore.a

INCLUDES = -I../include -I.
