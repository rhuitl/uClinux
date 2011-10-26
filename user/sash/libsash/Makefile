
LIB = libsash.a
CHOPSRC = utils.c
LIBOBJS = intflag.o modestring.o timestring.o isadir.o copyfile.o \
	buildname.o expandwildcards.o namesort.o match.o makeargs.o \
	makestring.o chunks.o expandenvvar.o

CFLAGS += -I../


all: $(EXEC) $(LIB)

$(LIBOBJS): $(CHOPSRC)
	$(CC) $(CFLAGS) -DL_$(basename $*) -o $(basename $*).o -c $^

$(LIB): $(LIB)($(LIBOBJS))
	$(RANLIB) $(LIB)

clean:
	rm -f $(LIB) $(EXEC) *.o
