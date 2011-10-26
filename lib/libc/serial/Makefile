
LIBC = ../libc.a

SRC = serial.c

OBJ = makerawtty.o makecookedtty.o setserial.o getserialp.o setserialp.o \
	tcspeed.o cfgetispeedn.o cfsetispeedn.o cfgetospeedn.o \
	cfsetospeedn.o writeall.o readall.o readaline.o hexdump.o \
	commstatus.o alarmstatus.o id485.o


all: $(LIBC)
	#@$(RM) $(OBJS)

$(LIBC): $(LIBC)($(OBJ))

$(LIBC)($(OBJ)): $(SRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

clean:
	-rm $(LIB) *.a *.o
