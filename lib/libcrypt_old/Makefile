#
# Makefile for libcrypt_old
#

CFLAGS += -Wall

#
# MMU hosts may want this included into shared libs
# so build it PIC on platforms that this makes sense
# on
#
ifneq ($(findstring nommu,$(ARCH)),nommu)
CFLAGS += -fPIC
endif

all: libcrypt_old.a

libcrypt_old.a:  crypt_old.o
	$(AR) crv $@ crypt_old.o
	$(RANLIB) $@

.PHONY: romfs
romfs:

.PHONY: clean
clean:
	-rm -f *.o libcrypt_old.a
