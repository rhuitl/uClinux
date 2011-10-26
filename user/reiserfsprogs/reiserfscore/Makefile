
CFLAGS += -I../include
OBJS   =  do_balan.o fix_node.o hashes.o ibalance.o lbalance.o \
          prints.o stree.o node_formats.o reiserfslib.o bitmap.o

all: libcore.a

libcore.a: $(OBJS)
	ar crv $@ $(OBJS)

romfs:

clean:
	rm -f $(OBJS) libcore.a
