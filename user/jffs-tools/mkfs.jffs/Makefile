
CC = gcc
INCLUDEDIR = /usr/include
CFLAGS = -Wall -I$(INCLUDEDIR)

all:	mkfs.jffs

clean:
	rm mkfs.jffs

mkfs.jffs:	mkfs.jffs.c
		$(CC) -o mkfs.jffs $(CFLAGS) mkfs.jffs.c
