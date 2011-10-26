
# CFLAGS += -I../libc/include

SRC = net.c
OBJS = openraw.o closeraw.o setifflags.o resetifflags.o setifaddr.o \
	setifdstaddr.o setifbrdaddr.o setifnetmask.o setifmtu.o \
	addroute.o maskaddress.o setifhwaddr.o

LIBNETOLD = libnetold.a


all: $(LIBNETOLD)

$(LIBNETOLD): $(LIBNETOLD)($(OBJS))
	$(RANLIB) $(LIBNETOLD)

$(LIBNETOLD)($(OBJS)): $(SRC)
	$(CC) $(CFLAGS) -DL_$(basename $*) -o $(basename $*).o -c $^
	$(AR) rv $(LIBNETOLD) $(basename $*).o

romfs:

clean:
	-rm -f $(LIBNETOLD) *.o

