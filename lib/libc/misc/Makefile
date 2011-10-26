# Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
# This file is part of the Linux-8086 C library and is distributed
# under the GNU Library General Public License.

LIBC=../libc.a
MSRC=aliases.c
MOBJ=abs.o labs.o bcopy.o bzero.o index.o raise.o rindex.o remove.o
# bcmp.o


ESRC=atexit.c
EOBJ=on_exit.o atexit.o __do_exit.o exit.o

GOBJ=atoi.o atol.o atoll.o ltoa.o ltostr.o \
     qsort.o bsearch.o rand.o lsearch.o getopt.o \
     itoa.o strtol.o sleep.o mkstemp.o mktemp.o mkdtemp.o \
     random.o tmpnam.o tempnam.o getpass.o getlogin.o gethostid.o abort.o \
     glob.o fnmatch.o insremque.o sysconf.o getdtablesize.o \
     mntent.o realpath.o scandir.o alphasort.o basename.o dirname.o \
     ftime.o

ifdef CONFIG_USER_BUSYBOX_SYSLOGD
GOBJ += syslog_bb.o
else
GOBJ += syslog.o
endif

UOBJ=getenv.o putenv.o popen.o system.o getcwd.o setenv.o unsetenv.o \
     execl.o execv.o execlp.o execvp.o execvep.o ffs.o

CSRC=ctype.c
COBJ=isalnum.o isalpha.o isascii.o iscntrl.o isdigit.o isgraph.o \
     islower.o isprint.o ispunct.o isspace.o isupper.o isxdigit.o \
     isxlower.o isxupper.o toascii.o tolower.o toupper.o isblank.o \
     __isctype_loc.o

OBJ=$(MOBJ) $(EOBJ) $(GOBJ) $(UOBJ) $(COBJ)

## No ELKS strtod() until BCC does 16 bit FP...
ifneq ($(LIB_CPU),i86)
OBJ+=strtod.o
endif

all: $(LIBC)
	#@$(RM) $(OBJ)

$(LIBC): $(LIBC)($(OBJ))

$(LIBC)($(MOBJ)): $(MSRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)($(EOBJ)): $(ESRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)($(COBJ)): $(CSRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

clean:
	rm -f *.o libc.a

$(LIBC)(strtol.o): strtol.c
	$(CC) -c $(CFLAGS) $*.c
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)(strtod.o): strtod.c
	$(CC) -c $(CFLAGS) $*.c
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)(glob.o): glob.c
	$(CC) -c $(CFLAGS) $*.c
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)(abort.o): abort.c
	$(CC) -c $(CFLAGS) $*.c
	$(AR) $(ARFLAGS) $@ $*.o

$(LIBC)(fnmatch.o): fnmatch.c
	$(CC) -c $(CFLAGS) $*.c
	$(AR) $(ARFLAGS) $@ $*.o

