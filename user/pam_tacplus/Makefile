#OPTIM=-ggdb3
#OPTIM=-O -s -m486
LIBTAC=./libtac
#CFLAGS=-pipe -fPIC -I$(LIBTAC)/include $(OPTIM)
#DEBUG1=-lmpr -L/home/kravietz/C/mpr-1.8 
#DEBUG2=-lefence
LIBS=-lpam -ldl -ltac -L$(LIBTAC)/lib $(DEBUG1) $(DEBUG2)
OBJ= support.o pam_tacplus.o

CFLAGS += -fPIC -I$(LIBTAC)/include

all: pam_tacplus.so

pam_tacplus.so: $(OBJ) Makefile $(LIBTAC)/lib/libtac.a
	$(CC) -shared $(OPTIM) -Xlinker -x -o pam_tacplus.so $(OBJ) $(LIBS)

$(LIBTAC)/lib/libtac.a:
	make -C libtac

clean:
	rm -f $(OBJ) pam_tacplus.so
	make -C libtac clean

install: pam_tacplus.so
	cp -f pam_tacplus.so /lib/security/pam_tacplus.so
	chmod a+rx /lib/security/pam_tacplus.so

romfs:
	$(ROMFSINST) /lib/security/pam_tacplus.so

support.o: support.c Makefile pam_tacplus.h support.h libtac/include/tacplus.h libtac/include/libtac.h
	$(CC) $(CFLAGS) -c support.c
pam_tacplus.o: pam_tacplus.c Makefile pam_tacplus.h support.h libtac/include/tacplus.h libtac/include/libtac.h
	$(CC) $(CFLAGS) -c pam_tacplus.c
