# Makefile for BCC tests
#
MODEL=s
CC = bcc -M$(MODEL)
CPP = gcc -E
CINCL = /usr/lib/bcc/include
AS = as86
LINK = $(CC) -v
COPT = -ansi -I$(CINCL) -c -O -DDEBUG=0
LOPT = -m >$*.map -M -d
AOPT = -0 -a -w
FD = msdos.b
FDSIZE = 1440
MFILE=/tmp/liloboot
LOOP=/dev/loop5

.SUFFIXES:	.com .S

.c.o:
	$(CC) $(COPT) -o $@ $< -A-l -A$*.lis

.o.com:
	$(LINK) $(LOPT) -o $@ $^

.s.o:
	$(AS) $(AOPT) -l $*.lis -o $@ $<

all:	check test4d.com test4.com bootdiagnostic.b.gz test5.com

check:	
	@if [ -x /usr/bin/bcc -o -x /usr/local/bin/bcc ]; then echo Okay; \
	else echo; echo "You don't seem to have the 'bcc' compiler from the 'dev86' package."; \
		echo; exit 1; fi

floppy:	bootdiagnostic.b.gz
	@echo
	@echo Insert a blank, formatted, floppy into drive 0
	@echo "Press <Enter> to continue, <^C> to abort ..."
	@read
	gzip -d <bootdiagnostic.b.gz | dd of=/dev/fd0 bs=1024

bootdiagnostic.b.gz:	sector.b test4.com test4d.com
	rm -rf $(MFILE) bootdiagnostic.b
	mkdir $(MFILE)
	dd if=/dev/zero of=bootdiagnostic.b bs=1024 count=$(FDSIZE)
	mkfs.msdos bootdiagnostic.b
	dd if=sector.b bs=2 count=1 of=floppy.b
	dd if=bootdiagnostic.b bs=2 skip=1 count=30 >>floppy.b
	dd if=sector.b bs=2 skip=31 count=225 >>floppy.b
#	umount $(MFILE) 2>/dev/null
	mount -t msdos -o loop=$(LOOP) bootdiagnostic.b $(MFILE)
	dd if=floppy.b of=$(LOOP) bs=512
	chown 0.0 *.com
	cp -ufv ../COPYING $(MFILE)
	cp -ufv test4.com $(MFILE)/hipboot.sys
	cp -ufv test4.com $(MFILE)/diag2sa.com
	cp -ufv test4d.com $(MFILE)/diag2.com
	if [ -f ../disk.b ]; then cp -ufv ../disk.b $(MFILE)/diag1.com; fi
	umount $(MFILE)
	rm -rf $(MFILE)
	gzip -9 <bootdiagnostic.b >bootdiagnostic.b.gz
	rm -f bootdiagnostic.b

test4.com:	test4.o bios_start.o cprintf.o

test5.com:	test5.o bios_start.o cprintf.o

sector.o:	sector.s
test4.o:	test4.c ../bdata.h
test5.o:	test5.c ../bdata.h
cprintf.o:	cprintf.c
bios_start.o:	bios.c
	bcc -c -u -I$(CINCL) -DL_bios_start -D__AS386_16__ -D__STANDALONE__ -o bios_start.o bios.c -v

test4d.o:	test4.c ../bdata.h
	bcc -Md $(COPT) -o $@ $<

test4d.com:	test4d.o
	bcc -Md $(LOPT) -o $@ $^

sector.s:	sector.S
	$(CPP) -traditional -o $@ $<

sector.img:	sector.o
	ld86 -0 -s -o $@ $<

sector.b:	sector.img
	dd if=$< of=$@ bs=32 skip=1

floppy.b:	sector.b
	dd if=sector.b bs=2 count=1 of=floppy.b
	dd if=$(FD) bs=2 skip=1 count=30 >>floppy.b
	dd if=sector.b bs=2 skip=31 count=225 >>floppy.b
	
tidy:
	rm -f *.map *.lis core

clean:	tidy
	rm -f *.o *.s *.img *.b *.com *.gz

spotless:  clean
	rm -f *~

