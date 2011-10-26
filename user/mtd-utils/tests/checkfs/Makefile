
all: checkfs makefiles

checkfs: checkfs.c Makefile common.h comm.o
	gcc -g -Wall checkfs.c comm.o -o checkfs

comm.o: comm.c Makefile
	gcc -g -Wall -c comm.c -o comm.o

makefiles: makefiles.c Makefile common.h
	gcc -g -Wall makefiles.c -o makefiles

clean:
	rm -f makefiles checkfs *~ *.o
