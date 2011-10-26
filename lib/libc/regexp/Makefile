
LIBC=../libc.a
OBJ=regexp.o regsub.o regerror.o
LSRC=regexp.c regsub.c regerror.c

all: $(LIBC)
	#@$(RM) $(OBJ)

$(LIBC): $(LIBC)($(OBJ))

$(LIBC)(regexp.o):	regexp.c ../include/regexp.h regmagic.h
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)(regsub.o):	regsub.c ../include/regexp.h regmagic.h
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)(regerror.o):	regerror.c
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

clean:
	rm -f libc.a *.o core mon.out timer.t.h dMakefile dtr try timer
