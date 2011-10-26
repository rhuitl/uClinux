-include ../lib.mak

SRC = BitVector.c
OBJS = BitVector.o
LIB = libbitvector.so
CFLAGS += -fPIC

all: $(LIB)

$(LIB): $(OBJS)
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ -lc

romfs:
	$(ROMFSINST) -d /lib/libbitvector.so

clean:
	-rm -f $(LIB) *.o
