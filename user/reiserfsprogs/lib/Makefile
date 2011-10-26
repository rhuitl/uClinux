
CFLAGS += -I../include
OBJS   =  io.o misc.o

all: libmisc.a

libmisc.a: $(OBJS)
	ar crv $@ $(OBJS)

romfs:

clean:
	rm -f $(OBJS) libmisc.a
