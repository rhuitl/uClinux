# Copyright (C) 1996 Robert de Bath <robert@mayday.compulink.co.uk>
# This file is part of the Linux-8086 C library and is distributed
# under the GNU Library General Public License.

LIBC=../libc.a
TSRC=termios.c
TOBJ=tcsetattr.o tcgetattr.o tcdrain.o tcflow.o tcflush.o tcsendbreak.o	\
     tcsetpgrp.o tcgetpgrp.o \
     cfgetospeed.o cfgetispeed.o cfsetospeed.o cfsetispeed.o cfmakeraw.o

#     cfgetospeedn.o cfgetispeedn.o cfsetospeedn.o cfsetispeedn.o tcspeed.o

OBJ=$(TOBJ) ttyname.o
# unlike everything else, this does not compile out of the box...
#  ttyname.o

all: $(LIBC)
	#@$(RM) $(OBJ)

$(LIBC): $(LIBC)($(OBJ))

$(LIBC)($(TOBJ)): $(TSRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

clean:
	rm -f *.o libc.a
