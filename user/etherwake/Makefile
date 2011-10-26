all: etherwake

etherwake: ether-wake.c
	$(CC) $(CFLAGS) -o etherwake ether-wake.c

clean:
	rm -f etherwake *.o
	
romfs:
	$(ROMFSINST) /sbin/etherwake
