#CC = gcc
#AR = ar
#DEBUG = -ggdb3 #-DDEBUGTAC
#DEBUG = -s -O -m486
#CFLAGS = -pipe -fPIC -I../include $(DEBUG)
CFLAGS += -fPIC -I../include
LIBRARY = libtac.a

LIBSRCS = 	connect.c \
			header.c \
			version.c \
			xalloc.c \
			messages.c \
			hdr_check.c \
			attrib.c \
			crypt.c \
			magic.c \
			md5.c \
			author_s.c \
			author_r.c \
			authen_s.c \
			authen_r.c \
			acct_r.c \
			acct_s.c


LIBOBJS = 	connect.o \
			header.o \
			version.o \
			xalloc.o \
			messages.o \
			hdr_check.o \
			attrib.o \
			crypt.o \
			magic.o \
			md5.o \
			author_s.o \
			author_r.o \
			authen_s.o \
			authen_r.o \
			acct_r.o \
			acct_s.o

.c.o:
	$(CC) $(CFLAGS) -c $<

$(LIBRARY): $(LIBOBJS) Makefile
	$(AR) rc $(LIBRARY) $(LIBOBJS)
	ranlib $(LIBRARY)

clean: 
	rm -f core $(LIBRARY) $(LIBOBJS)
