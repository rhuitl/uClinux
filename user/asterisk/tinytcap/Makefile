OBJS=tinytcap.o

all: libtermcap.a

libtermcap.a: $(OBJS)
	ar rv $@ $(OBJS)
	ranlib $@

install:

clean:
	rm -f libtermcap.a *.o
