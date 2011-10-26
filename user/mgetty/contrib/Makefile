#
# Makefile for miscellaneous stuff in contrib
#
#
# settings for CC, CFLAGS imported from above
# (call with "make contrib-all" from top level mgetty directory)

all: faxin

FIOBJS=faxin.o \
	../modem.o ../faxlib.o ../faxrec.o ../faxsend.o ../faxhng.o \
	../logfile.o ../io.o ../tio.o ../getdisk.o

faxin: $(FIOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o faxin $(FIOBJS) $(LIBS)

faxin.o: faxin.c ../mgetty.h ../policy.h
	$(CC) $(CFLAGS) $(LDFLAGS) -I.. -c -o faxin.o faxin.c $(LIBS)

clean:
	rm -f *.o

fullclean:
	rm -f *.o faxin




