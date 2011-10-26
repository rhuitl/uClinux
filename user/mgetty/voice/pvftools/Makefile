#
# Makefile
#
# This is the Makefile for the pvftools.
#
# $Id: Makefile,v 1.4 1998/09/09 21:07:41 gert Exp $
#

VOICELIBS=$(LIBPVF) $(LIBUTIL)

.c.o:
	$(CC) $(CFLAGS) -c $*.c

all: $(PVFTOOLS)

install:

clean:
	@$(RM) -f $(PVFTOOLS) *.o

fullclean: clean

pvfamp: pvfamp.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvfamp pvfamp.o $(VOICELIBS) $(LIBS) 

pvfcut: pvfcut.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvfcut pvfcut.o $(VOICELIBS) $(LIBS) 

pvfecho: pvfecho.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvfecho pvfecho.o $(VOICELIBS) $(LIBS) 

pvffile: pvffile.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvffile pvffile.o $(VOICELIBS) $(LIBS) 

pvffilter: pvffilter.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvffilter pvffilter.o $(VOICELIBS) $(LIBS) -lm

pvffft: pvffft.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvffft pvffft.o $(VOICELIBS) $(LIBS) -lm

pvfmix: pvfmix.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvfmix pvfmix.o $(VOICELIBS) $(LIBS) 

pvfnoise: pvfnoise.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvfnoise pvfnoise.o $(VOICELIBS) $(LIBS) 

pvfreverse: pvfreverse.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvfreverse pvfreverse.o $(VOICELIBS) $(LIBS) 

pvfsine: pvfsine.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvfsine pvfsine.o $(VOICELIBS) $(LIBS) -lm

pvfspeed: pvfspeed.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvfspeed pvfspeed.o $(VOICELIBS) $(LIBS) 

pvftormd: pvftormd.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvftormd pvftormd.o $(VOICELIBS) $(LIBS) \
	 $(LIBGSM)

rmdtopvf: rmdtopvf.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o rmdtopvf rmdtopvf.o $(VOICELIBS) $(LIBS) \
	 $(LIBGSM)

rmdfile: rmdfile.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o rmdfile rmdfile.o $(VOICELIBS) $(LIBS) 

pvftovoc: pvftovoc.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvftovoc pvftovoc.o $(VOICELIBS) $(LIBS) 

voctopvf: voctopvf.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o voctopvf voctopvf.o $(VOICELIBS) $(LIBS) 

pvftolin: pvftolin.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvftolin pvftolin.o $(VOICELIBS) $(LIBS) 

lintopvf: lintopvf.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o lintopvf lintopvf.o $(VOICELIBS) $(LIBS) 

pvftobasic: pvftobasic.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvftobasic pvftobasic.o $(VOICELIBS) $(LIBS) 

basictopvf: basictopvf.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o basictopvf basictopvf.o $(VOICELIBS) $(LIBS) 

pvftoau: pvftoau.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvftoau pvftoau.o $(VOICELIBS) $(LIBS) 

autopvf: autopvf.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o autopvf autopvf.o $(VOICELIBS) $(LIBS) 

pvftowav: pvftowav.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o pvftowav pvftowav.o $(VOICELIBS) $(LIBS) 

wavtopvf: wavtopvf.o $(VOICELIBS)
	$(CC) $(LDFLAGS) -o wavtopvf wavtopvf.o $(VOICELIBS) $(LIBS) 

include depend
