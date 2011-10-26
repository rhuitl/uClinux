#
# Makefile
#
# This is the Makefile for libvoice.
#
# $Id: Makefile,v 1.4 1998/09/09 21:08:10 gert Exp $
#

VMOBJS=main.o event.o usage.o

MGETTYOBJS=../../cnd.o ../../faxhng.o ../../faxlib.o ../../faxrec.o \
	../../faxrecp.o ../../faxsend.o ../../gettydefs.o ../../login.o \
	../../logname.o ../../utmp.o

VOICELIBS=$(MGETTYLIB) $(LIBVOICE) $(LIBUTIL)

.c.o:
	$(CC) $(CFLAGS) -c $*.c

all: $(VMOBJS) vm

install:

clean:
	@$(RM) -f vm $(VMOBJS)

fullclean: clean

vm: $(VMOBJS) $(VOICELIBS)
	$(CC) $(LDFLAGS) -o vm $(VMOBJS) $(MGETTYOBJS) $(VOICELIBS) $(LIBS)

include depend
