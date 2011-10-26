#CFLAGS = -pipe -fPIC -I../include $(OPTIMIZE)
CFLAGS += -I../include
LIBRARY = libtac.a

LIBSRCS = 	connect.c \
			header.c \
			version.c \
			xalloc.c \
			messages.c \
			hdr_check.c \
			attrib.c \
			crypt.c \
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
			author_s.o \
			author_r.o \
			authen_s.o \
			authen_r.o \
			acct_r.o \
			acct_s.o

ifneq ($(findstring uClibc,$(LIBCDIR)),uClibc)
LIBOBJS += md5.o
LIBSRCS += md5.c
endif

all: $(LIBRARY)

$(LIBRARY): $(LIBOBJS) Makefile
	$(AR) rc $(LIBRARY) $(LIBOBJS)
	$(RANLIB) $(LIBRARY)

clean: 
	rm -f core $(LIBRARY) $(LIBOBJS)
