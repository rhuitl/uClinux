CC = gcc
CFLAGS = -W -Wall -O2 -g
CPPFLAGS = -I/usr/src/linux/include/

EXECS = uCmkimage uCheader
OBJS = md5.o

ifndef MD5HEADER_PATH
MD5HEADER_PATH = ..
endif


all:  link md5.o $(EXECS)

link:
	ln -sf $(MD5HEADER_PATH)/md5.h md5.h

md5.o:
	$(CC) -c $(MD5HEADER_PATH)/md5.c

$(EXECS):
	$(CC) -o $@ $@.c $(OBJS)

clean:
	-rm -f $(EXECS) $(OBJS) uCheader.o md5.h

