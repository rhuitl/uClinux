#	@(#)Makefile	8.2 (Berkeley) 4/28/95

PROG=	cksum
CFLAGS+=-Wall -O
SRCS=	cksum.c crc.c print.c sum1.c sum2.c crc32.c
OBJS=   cksum.o crc.o print.o sum1.o sum2.o crc32.o
LINKS=	${BINDIR}/cksum ${BINDIR}/sum
MLINKS=	cksum.1 sum.1
EXEC=	$(PROG)

# Stack length used:  16672
FLTFLAGS += -s 32768

$(PROG): $(OBJS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

