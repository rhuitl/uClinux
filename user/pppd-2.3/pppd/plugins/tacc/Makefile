## debugging flags
## -DDEBUGTAC will cause every TACACS+ function report it's progress
## and errors to syslog(3)
## -lefence links ElectricFence bounds checking library
#CFLAGS = -ggdb3 -DDEBUGTAC
#LDFLAGS = -ggdb3 -lefence

## normal flags
OPTIMIZE = -O2 -m486 -s -Wall
CFLAGS = $(OPTIMIZE)
LDFLAGS = -s

## uncomment this if using BIND 8.1
#CFLAGS += -D__inet_aton=inet_aton

## standard includes
CFLAGS += -Iinclude -Ilib -Iextras

## uncomment -lutil if using glibc/FreeBSD
LDFLAGS += -Llib -ltac -lutil
## uncomment this and comment out the above on old FreeBSD installations
# LDFLAGS += -lutil

OBJ = tacc.o
OBJ += extras/getopt.o

## uncomment on old FreeBSD installations
#OBJ += lib/acct_r.o lib/acct_s.o lib/attrib.o lib/authen_r.o lib/authen_s.o lib/author_r.o lib/author_s.o lib/connect.o lib/crypt.o lib/hdr_check.o lib/header.o lib/magic.o lib/md5.o lib/messages.o lib/version.o lib/xalloc.o

LD = gcc
CC = gcc

all: tacc

libtac: lib
	(cd lib; make OPTIMIZE="$(OPTIMIZE)")

support: extras 
	(cd extras; make)

tacc: support libtac tacc.o 
	$(LD)  -o tacc $(OBJ) $(LDFLAGS)

install: tacc tacc.1
	install -s tacc /usr/local/sbin
	install tacc.1 /usr/local/man/man1

clean:
	rm -f *.o tacc
	(cd lib; make clean)
	(cd extras; make clean)
