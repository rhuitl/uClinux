ifndef CFLAGS
CFLAGS = -O2 -Wall
endif

# Include directory for CVS version
CFLAGS += -I../driver/modules

all: prism2_srec hostap_crypt_conf hostap_diag hostap_io_debug hostap_rid

prism2_srec: prism2_srec.o util.o

prism2_srec.o: prism2_srec.c util.h

hostap_crypt_conf: hostap_crypt_conf.c

hostap_diag: hostap_diag.o util.o
	$(CC) $(LDFLAGS) -o $@ hostap_diag.o util.o $(LDLIBS)

hostap_diag.o: hostap_diag.c util.h

util.o: util.c util.h

hostap_io_debug: hostap_io_debug.c
	$(CC) $(LDFLAGS) -o $@ $(CFLAGS) hostap_io_debug.c $(LDLIBS)

hostap_rid: hostap_rid.o util.o
	$(CC) $(LDFLAGS) -o $@ $(CFLAGS) hostap_rid.o util.o $(LDLIBS)

hostap_rid.o: hostap_rid.c util.h

clean:
	rm -f prism2_srec hostap_crypt_conf hostap_diag hostap_rid *.o

romfs:
	$(ROMFSINST) /bin/hostap_diag
