## This libcap (for proftpd) is originally from libcap-1.10,
## at ftp://linux.kernel.org/pub/libs/security/linux-privs.
## This interface is SPECIFIC TO THE LINUX 2.2 KERNEL!!!  IT IS NOT GUARANTEED
## TO WORK ON ANY PRIOR OR LATER VERSION (ie: 2.1.x or 2.3.x).
## If this library stops working, please contact core@proftpd.org.

VPATH=../../../lib/libcap

#
# Library version
#
LIBNAME=libcap.a
FILES=cap_alloc cap_proc cap_extint cap_flag cap_text cap_sys
INCLS=libcap.h cap_names.h $(INCS)
OBJS=$(addsuffix .o, $(FILES))
CFLAGS += -I.

all: $(LIBNAME)

#
# This is built to run on the build host, do not use cross compiler
#
_makenames: _makenames.c cap_names.sed
	gcc -I. -O $< -o $@

cap_names.h: _makenames
	./_makenames > cap_names.h

cap_names.sed: Makefile /usr/include/linux/capability.h
	@echo "=> making cap_names.c from <linux/capability.h>"
	@sed -ne '/^#define[ \t]CAP[_A-Z]\+[ \t]\+[0-9]\+/{s/^#define \([^ \t]*\)[ \t]*\([^ \t]*\)/  \{ \2, \"\1\" \},/;y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/;p;}' < /usr/include/linux/capability.h | fgrep -v 0x > cap_names.sed

$(LIBNAME): $(OBJS)
	ar rcu $@ $(OBJS)

%.o: %.c $(INCLS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(LOCALCLEAN)
	rm -f $(OBJS) $(LIBNAME)*
	rm -f cap_names.h cap_names.sed _makenames

