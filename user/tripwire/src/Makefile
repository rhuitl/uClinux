# $Id: Makefile,v 1.26 1994/07/25 15:40:54 gkim Exp $
#
# 	Tripwire build
#

# CFLAGS = -O
# The default stack size isn't quite enough.
# __probe_stack_size indicates about 27000 bytes are needed minimally
FLTFLAGS += -s 32000

OFILES = 	config.parse.o main.o list.o ignorevec.o dbase.build.o \
		utils.o preen.o preen.interp.o preen.report.o \
		nullsig.o config.prim.o dbase.update.o \
		config.pre.o help.o \
		$(OSIGS)

SIGDIR	  = ../sigs
SIG1DIR   = $(SIGDIR)/md5
SIG2DIR   = $(SIGDIR)/snefru
SIG3DIR   = $(SIGDIR)/crc32
SIG4DIR   = $(SIGDIR)/crc
SIG5DIR   = $(SIGDIR)/md4
SIG6DIR   = $(SIGDIR)/md2
SIG7DIR   = $(SIGDIR)/sha
SIG8DIR   = $(SIGDIR)/haval

SIGDIRS	  = $(SIG1DIR) $(SIG2DIR) $(SIG3DIR) $(SIG4DIR) $(SIG5DIR) \
	    $(SIG6DIR) $(SIG7DIR) $(SIG8DIR) $(SIG9DIR)

OSIG1	  = $(SIG1DIR)/md5wrapper.o $(SIG1DIR)/md5.o
OSIG2	  = $(SIG2DIR)/snefru.o
OSIG3	  = $(SIG3DIR)/crc32.o
OSIG4	  = $(SIG4DIR)/crc.o
OSIG5	  = $(SIG5DIR)/md4.o $(SIG5DIR)/md4wrapper.o
OSIG6	  = $(SIG6DIR)/md2.o $(SIG6DIR)/md2wrapper.o
OSIG7	  = $(SIG7DIR)/sha.o $(SIG7DIR)/shawrapper.o
OSIG8	  = $(SIG8DIR)/haval.o $(SIG8DIR)/havalwrapper.o

OSIGS	  = $(OSIG1) $(OSIG2) $(OSIG3) $(OSIG4) $(OSIG5) $(OSIG6) $(OSIG7) \
	    $(OSIG8) $(OSIG9)

CSIG1	  = $(SIG1DIR)/md5wrapper.c $(SIG1DIR)/md5.c
CSIG2	  = $(SIG2DIR)/snefru.c
CSIG3	  = $(SIG3DIR)/crc32.c
CSIG4	  = $(SIG4DIR)/crc.c
CSIG5	  = $(SIG5DIR)/md4.c $(SIG5DIR)/md4wrapper.c
CSIG6	  = $(SIG6DIR)/md2.c $(SIG6DIR)/md2wrapper.c
CSIG7	  = $(SIG7DIR)/sha.c $(SIG7DIR)/shawrapper.c
CSIG8	  = $(SIG8DIR)/haval.c $(SIG8DIR)/havalwrapper.c

CSIGS	  = $(CSIG1) $(CSIG2) $(CSIG3) $(CSIG4) $(CSIG5) $(CSIG6) $(CSIG7) \
	    $(CSIG8) $(CSIG9)

CFILES = 	config.parse.c main.c list.c ignorevec.c dbase.build.c \
		utils.c preen.c preen.interp.c preen.report.c \
		nullsig.c config.prim.c dbase.update.c \
		config.pre.c help.c \
		$(CSIGS)

###

all:	tripwire siggen

tripwire:	$(P) help.c $(OFILES) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OFILES) $(LIBS) $(LDLIBS)

$(OSIG1):	../include/byteorder.h
	(cd $(SIG1DIR); make CC="$(CC)" CFLAGS="$(CFLAGS) -I. -I..")
$(OSIG2):	../include/byteorder.h
	(cd $(SIG2DIR); make CC="$(CC)" CFLAGS="$(CFLAGS) -I. -I..")
$(OSIG3):	../include/byteorder.h
	(cd $(SIG3DIR); make CC="$(CC)" CFLAGS="$(CFLAGS) -I. -I..")
$(OSIG4):	../include/byteorder.h
	(cd $(SIG4DIR); make CC="$(CC)" CFLAGS="$(CFLAGS) -I. -I..")
$(OSIG5):	../include/byteorder.h
	(cd $(SIG5DIR); make CC="$(CC)" CFLAGS="$(CFLAGS) -I. -I..")
$(OSIG6):	../include/byteorder.h
	(cd $(SIG6DIR); make CC="$(CC)" CFLAGS="$(CFLAGS) -I. -I..")
$(OSIG7):	../include/byteorder.h
	(cd $(SIG7DIR); make CC="$(CC)" CFLAGS="$(CFLAGS) -I. -I..")
$(OSIG8):	../include/byteorder.h
	(cd $(SIG8DIR); make CC="$(CC)" CFLAGS="$(CFLAGS) -I. -I..")

../include/byteorder.h ../include/inode.h:
	(cd ../aux; make CC=$(CC) CFLAGS="$(CFLAGS)"  \
	LDFLAGS="$(LDFLAGS)" CPP="$(CPP)" SHELL=$(SHELL) all)

help.c:	help.txt help.sh
	$(SHELL) help.sh help.txt > help.c


# need $(LDFLAGS) because this may interact with the way nullsig.o and
# utils.o were compiled
siggen:	$(OSIGS) siggen.o utils.o nullsig.o Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o siggen siggen.c $(OSIGS) nullsig.o utils.o $(LIBS) $(LDLIBS)
	
config.lex.c:	config.pre.l
	$(LEX) config.pre.l
	mv lex.yy.c config.lex.c

config.pre.c:	config.lex.c config.pre.y
	$(YACC) config.pre.y
	sed 's/lex\.yy\.c/config.lex.c/' < y.tab.c > config.pre.c 
	rm y.tab.c

.c.o:
	$(CC) $(CFLAGS) -c $<

install:	tripwire
	$(INSTALL) tripwire $(DESTDIR)

clean:
	-rm -f $(OFILES) config.lex.c config.pre.c y.tab.c lex.yy.c help.c \
	siggen.o twconvert.o core .pure cscope.out *.gdb *.elf siggen tripwire
	-for i in $(SIGDIRS); do \
	    make -C $$i clean; \
	done


clobber:	clean
	-rm -f tripwire siggen twconvert

cscope.files:
	echo siggen.c $(CFILES) > cscope.files

#  Some other dependencies

config.lex.o: config.lex.c
config.parse.o: config.parse.c
config.parse.o: ../include/config.h
config.parse.o: ../include/list.h
config.parse.o: ../include/tripwire.h
config.parse.o: ../sigs/snefru/snefru.h
config.parse.o: ../sigs/md5/md5.h
config.parse.o: ../sigs/crc32/crc32.h
config.parse.o: ../sigs/crc/crc.h
config.parse.o: ../sigs/md2/md2.h
config.parse.o: ../sigs/md4/md4.h
config.parse.o: ../include/inode.h
config.pre.o: config.pre.c
config.pre.o: ../include/config.h
config.pre.o: ../include/list.h
config.pre.o: ../include/tripwire.h
config.pre.o: ../sigs/snefru/snefru.h
config.pre.o: ../sigs/md5/md5.h
config.pre.o: ../sigs/crc32/crc32.h
config.pre.o: ../sigs/crc/crc.h
config.pre.o: ../sigs/md2/md2.h
config.pre.o: ../sigs/md4/md4.h
config.pre.o: ../include/inode.h
config.pre.o: ./config.lex.c
config.prim.o: config.prim.c
config.prim.o: ../include/config.h
config.prim.o: ../include/tripwire.h
config.prim.o: ../sigs/snefru/snefru.h
config.prim.o: ../sigs/md5/md5.h
config.prim.o: ../sigs/crc32/crc32.h
config.prim.o: ../sigs/crc/crc.h
config.prim.o: ../sigs/md2/md2.h
config.prim.o: ../sigs/md4/md4.h
config.prim.o: ../include/inode.h
config.prim.o: ../include/list.h
dbase.build.o: dbase.build.c
dbase.build.o: ../include/config.h
dbase.build.o: ../include/list.h
dbase.build.o: ../include/tripwire.h
dbase.build.o: ../sigs/snefru/snefru.h
dbase.build.o: ../sigs/md5/md5.h
dbase.build.o: ../sigs/crc32/crc32.h
dbase.build.o: ../sigs/crc/crc.h
dbase.build.o: ../sigs/md2/md2.h
dbase.build.o: ../sigs/md4/md4.h
dbase.build.o: ../include/inode.h
dbase.update.o: dbase.update.c
dbase.update.o: ../include/config.h
dbase.update.o: ../include/list.h
dbase.update.o: ../include/tripwire.h
dbase.update.o: ../sigs/snefru/snefru.h
dbase.update.o: ../sigs/md5/md5.h
dbase.update.o: ../sigs/crc32/crc32.h
dbase.update.o: ../sigs/crc/crc.h
dbase.update.o: ../sigs/md2/md2.h
dbase.update.o: ../sigs/md4/md4.h
dbase.update.o: ../include/inode.h
ignorevec.o: ignorevec.c
ignorevec.o: ../include/config.h
ignorevec.o: ../include/list.h
ignorevec.o: ../include/tripwire.h
ignorevec.o: ../sigs/snefru/snefru.h
ignorevec.o: ../sigs/md5/md5.h
ignorevec.o: ../sigs/crc32/crc32.h
ignorevec.o: ../sigs/crc/crc.h
ignorevec.o: ../sigs/md2/md2.h
ignorevec.o: ../sigs/md4/md4.h
ignorevec.o: ../include/inode.h
list.o: list.c
list.o: ../include/config.h
list.o: ../include/list.h
main.o: main.c
main.o: ../include/config.h
main.o: ../include/list.h
main.o: ../include/tripwire.h
main.o: ../sigs/snefru/snefru.h
main.o: ../sigs/md5/md5.h
main.o: ../sigs/crc32/crc32.h
main.o: ../sigs/crc/crc.h
main.o: ../sigs/md2/md2.h
main.o: ../sigs/md4/md4.h
main.o: ../include/inode.h
main.o: ../include/patchlevel.h
nullsig.o: nullsig.c
nullsig.o: ../include/config.h
nullsig.o: ../include/tripwire.h
nullsig.o: ../sigs/snefru/snefru.h
nullsig.o: ../sigs/md5/md5.h
nullsig.o: ../sigs/crc32/crc32.h
nullsig.o: ../sigs/crc/crc.h
nullsig.o: ../sigs/md2/md2.h
nullsig.o: ../sigs/md4/md4.h
nullsig.o: ../include/inode.h
nullsig.o: ../include/sigs.h
preen.o: preen.c
preen.o: ../include/config.h
preen.o: ../include/list.h
preen.o: ../include/tripwire.h
preen.o: ../sigs/snefru/snefru.h
preen.o: ../sigs/md5/md5.h
preen.o: ../sigs/crc32/crc32.h
preen.o: ../sigs/crc/crc.h
preen.o: ../sigs/md2/md2.h
preen.o: ../sigs/md4/md4.h
preen.o: ../include/inode.h
preen.interp.o: preen.interp.c
preen.interp.o: ../include/config.h
preen.interp.o: ../include/list.h
preen.interp.o: ../include/tripwire.h
preen.interp.o: ../sigs/snefru/snefru.h
preen.interp.o: ../sigs/md5/md5.h
preen.interp.o: ../sigs/crc32/crc32.h
preen.interp.o: ../sigs/crc/crc.h
preen.interp.o: ../sigs/md2/md2.h
preen.interp.o: ../sigs/md4/md4.h
preen.interp.o: ../include/inode.h
preen.report.o: preen.report.c
preen.report.o: ../include/config.h
preen.report.o: ../include/list.h
preen.report.o: ../include/tripwire.h
preen.report.o: ../sigs/snefru/snefru.h
preen.report.o: ../sigs/md5/md5.h
preen.report.o: ../sigs/crc32/crc32.h
preen.report.o: ../sigs/crc/crc.h
preen.report.o: ../sigs/md2/md2.h
preen.report.o: ../sigs/md4/md4.h
preen.report.o: ../include/inode.h
siggen.o: siggen.c
siggen.o: ../include/config.h
siggen.o: ../include/list.h
siggen.o: ../include/tripwire.h
siggen.o: ../sigs/snefru/snefru.h
siggen.o: ../sigs/md5/md5.h
siggen.o: ../sigs/crc32/crc32.h
siggen.o: ../sigs/crc/crc.h
siggen.o: ../sigs/md2/md2.h
siggen.o: ../sigs/md4/md4.h
siggen.o: ../include/inode.h
utils.o: utils.c
utils.o: ../include/config.h
utils.o: ../include/list.h
utils.o: ../include/tripwire.h
utils.o: ../sigs/snefru/snefru.h
utils.o: ../sigs/md5/md5.h
utils.o: ../sigs/crc32/crc32.h
utils.o: ../sigs/crc/crc.h
utils.o: ../sigs/md2/md2.h
utils.o: ../sigs/md4/md4.h
utils.o: ../include/inode.h
