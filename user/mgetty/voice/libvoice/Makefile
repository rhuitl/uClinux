#
# Makefile
#
# This is the Makefile for libvoice.
#
# $Id: Makefile,v 1.18 2005/03/13 17:27:46 gert Exp $
#

VOICEOBJS=analyze.o close.o command.o detect.o event.o flush.o \
	init.o mode.o open.o play.o read.o record.o shell.o signal.o write.o \
	voice_fax.o device_mode_names.o \
	Cirrus_Logic.o Digi_RAS.o Dolphin.o Dr_Neuhaus.o Elsa.o V253modem.o IS_101.o \
	ISDN4Linux.o Lucent.o Multitech_2834.o Rockwell.o Sierra.o Supra.o UMC.o \
	US_Robotics.o ZyXEL_1496.o ZyXEL_2864.o ZyXEL_Omni56K.o \
	Multitech_5634.o Multitech_5634ZPX.o Multitech_5634ZPX_ISA.o \
	Multitech_5600ZDXv.o Supra56ePRO.o V253ugly.o

.c.o:
	$(CC) $(CFLAGS) -c $*.c

all: libvoice.a

libvoice.a: $(VOICEOBJS)
	$(RM) -f libvoice.a
	$(AR) $(ARFLAGS) libvoice.a $(VOICEOBJS)
	-$(RANLIB) libvoice.a

install:

clean:
	@$(RM) -f libvoice.a $(VOICEOBJS)

fullclean: clean
	@$(RM) -f depend

depend: *.c
	$(CC) $(CFLAGS) -MM -c *.c > depend

include depend
