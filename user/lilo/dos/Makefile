# Makefile for BCC compilation of 'lilo.com'
#
# Known to work with BCC version 0.16.15
# Known not to work with BCC version 0.16.10
#
MODEL=d
CC = bcc -M$(MODEL)
CPP = gcc -E
CINCL = /usr/lib/bcc/include
AS = as86
LINK = $(CC) -v
COPT = -ansi -I.. -I$(CINCL) -c -O $(CFLAGS)
LOPT = -m >$*.map -M -d
AOPT = -0 -a -w
CFLAGS = -DLCF_IGNORECASE -DLCF_DSECS=3 -DLCF_PASS160

.SUFFIXES:	.com .S

HFILES = ../lilo.h ../bitmap.h ../cfg.h ../config.h ../common.h ../map.h ../temp.h ../version.h

.c.o:
	$(CC) $(COPT) -o $@ ../$*.c

.o.com:
	$(LINK) $(LOPT) -o $@ $^

.s.o:
	$(AS) $(AOPT) -l $*.lis -o $@ $<




all:	check lilo.com

alles:	all
	cp -ufv lilo.com lilo.map /dosC/boot

check:
	@echo $(CFLAGS)
	@if [ -x /usr/bin/bcc -o -x /usr/local/bin/bcc ]; then echo Okay; \
	else echo; echo "You don't seem to have the 'bcc' compiler from the 'dev86' package."; \
		echo; exit 1; fi


lilo.com:	lilo.o common.o cfg.o map.o # cprintf.o

lilo.o:		../lilo.c $(HFILES)
	$(CC) $(COPT) -o $@  ../$*.c

cfg.o:		../cfg.c $(HFILES)
	$(CC) $(COPT) -o $@  ../$*.c

common.o:	../common.c $(HFILES)
	$(CC) $(COPT) -o $@  ../$*.c

cprintf.o:	../cprintf.c $(HFILES)
	$(CC) $(COPT) -o $@  ../$*.c

map.o:		../map.c $(HFILES)
	$(CC) $(COPT) -o $@  ../$*.c



tidy:
	rm -f *.map *.lis core

clean:	tidy
	rm -f *.o *.s *.img *.b *.com *.gz

spotless:  clean
	rm -f *~ *.c *.h

