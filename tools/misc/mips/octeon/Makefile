ifndef CROSS_COMPILE
ifneq ($(shell which mips-linux-20071101-gcc),)
CROSS_COMPILE  = mips-linux-20071101-
else
CROSS_COMPILE  = mips-linux-
endif
endif

CCFLAGS = -mabi=64 -G 0 -mlong-calls -mno-abicalls -fno-pic -msoft-float -ffreestanding -O2
LDFLAGS = -melf64btsmip -nostdlib

OBJS = start.o flasher.o


all: flasher

flasher: $(OBJS)
	$(CROSS_COMPILE)ld $(LDFLAGS) -T flasher.ld -static -o flasher $(OBJS)

%.o: %.S
	$(CROSS_COMPILE)gcc $(CFLAGS) $(CCFLAGS) -c $<

%.o: %.c
	$(CROSS_COMPILE)gcc $(CFLAGS) $(CCFLAGS) -c $<

boot.elf: boot.bin
	$(CROSS_COMPILE)ld -Tdata=0x00100000 -o boot.elf -b binary boot.bin

clean:
	rm -f flasher *.o boot.elf

