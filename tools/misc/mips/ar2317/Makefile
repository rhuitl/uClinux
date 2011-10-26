
CFLAGS = -mlong-calls -mno-abicalls -fno-pic -O

OBJS = start.o flasher.o


all: flasher

flasher: $(OBJS)
	mips-linux-ld -T flasher.ld -static -nostdlib -o flasher $(OBJS)

%.o: %.S
	mips-linux-gcc $(CFLAGS) -c $<

%.o: %.c
	mips-linux-gcc $(CFLAGS) -c $<

boot.elf: boot.bin
	mips-linux-ld -Tdata=0x00100000 -o boot.elf -b binary boot.bin

clean:
	rm -f flasher *.o boot.elf

