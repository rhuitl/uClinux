
LIBC=../libc.a
MSRC=alloc.c
MOBJ=malloc.o free.o calloc.o realloc.o

OBJ=$(MOBJ)

all: $(LIBC)
	#@$(RM) $(OBJ)

$(LIBC): $(LIBC)($(OBJ))

$(LIBC)($(MOBJ)): $(MSRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

clean:
	rm -f *.o

