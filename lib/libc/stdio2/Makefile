# Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
# This file is part of the Linux-8086 C library and is distributed
# under the GNU Library General Public License.

LIBC=../libc.a
ASRC=stdio.c
AOBJ=_stdio_init.o fputc.o fgetc.o fflush.o fgets.o gets.o fputs.o	\
     puts.o fread.o fwrite.o fopen.o fclose.o fseek.o rewind.o ftell.o	\
     setbuffer.o setvbuf.o ungetc.o fgetpos.o fsetpos.o

PSRC=printf.c
POBJ=printf.o sprintf.o fprintf.o snprintf.o vprintf.o vsprintf.o \
     vfprintf.o vfnprintf.o vsnprintf.o asprintf.o vasprintf.o

SSRC=scanf.c
SOBJ=scanf.o sscanf.o fscanf.o vscanf.o vsscanf.o vfscanf.o

ifdef CONFIG_BINFMT_SHARED_FLAT
CFLAGS += -DFLOATS=1
endif

OBJ= $(AOBJ) $(POBJ) $(SOBJ) dputs.o getdelim.o getline.o

all: $(LIBC) $(OBJ)
	#@$(RM) $(OBJ)

$(LIBC): $(LIBC)($(OBJ))

$(LIBC)($(AOBJ)): $(ASRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)($(POBJ)): $(PSRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)($(SOBJ)): $(SSRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

transfer:
	-@rm -f ../include/stdio.h
	cp -p stdio.h ../include/.

clean:
	rm -f *.o libc.a

$(LIBC)($(OBJ)): stdio.h

