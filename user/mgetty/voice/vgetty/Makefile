#
# Makefile
#
# This is the Makefile for vgetty.
#
# $Id: Makefile,v 1.6 2000/08/14 19:51:55 gert Exp $
#

VGETTYOBJS=vgetty.o answer.o button.o event.o message.o rings.o

MGETTYOBJS=../../cnd.o ../../conf_mg.o ../../do_chat.o ../../do_stat.o \
	../../faxhng.o ../../faxlib.o ../../faxrec.o ../../faxrecp.o \
	../../faxsend.o ../../gettydefs.o ../../login.o ../../logname.o \
	../../mg_m_init.o ../../utmp.o ../../ring.o

VOICELIBS=$(MGETTYLIB) $(LIBVOICE) $(LIBUTIL)

.c.o:
	$(CC) $(CFLAGS) -c $*.c

all: vgetty

install:

clean:
	@$(RM) -f vgetty $(VGETTYOBJS)

fullclean: clean

vgetty.o: ../../mgetty.o
	@$(RM) -f vgetty.o
	@cd ../.. ;\
	$(RM) -f vgetty.c ;\
	$(LN) -s mgetty.c vgetty.c
	cd ../.. ;\
	$(CC) $(CFLAGS) -DVOICE -DFAX_SPOOL_IN=\"$(FAX_SPOOL_IN)\" \
		-DVARRUNDIR=\"$(VARRUNDIR)\" -c vgetty.c
	@$(MV) ../../vgetty.o vgetty.o

vgetty: $(VGETTYOBJS) $(MGETTYOBJS) $(VOICELIBS)
	$(CC) $(LDFLAGS) -o vgetty $(VGETTYOBJS) $(MGETTYOBJS) $(VOICELIBS) \
	 $(LIBS)

include depend
