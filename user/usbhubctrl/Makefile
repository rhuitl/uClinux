all: 
	$(CC) $(CFLAGS) -o hub-ctrl hub-ctrl.c

clean:
	rm -f hub-ctrl *.o
	
romfs:
	$(ROMFSINST) /sbin/hub-ctrl
