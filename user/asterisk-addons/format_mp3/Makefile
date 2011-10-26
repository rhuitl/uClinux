MODS=format_mp3.so
MP3OBJS=common.o dct64_i386.o decode_ntom.o layer3.o tabinit.o interface.o format_mp3.o

CFLAGS=$(ASTERISK_INCLUDE) -pipe -fPIC -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations $(DEBUG) $(INCLUDE) -D_REENTRANT -D_GNU_SOURCE #-DMAKE_VALGRIND_HAPPY

OSARCH=$(shell uname -s)

ifeq (${OSARCH},Linux)
PROC=$(shell uname -m)
ifeq ($(PROC),x86_64)
# You must have GCC 3.4 to use k8, otherwise use athlon
PROC=k8
#PROC=athlon
#OPTIONS+=-m64
endif
ifeq ($(PROC),sparc64)
#The problem with sparc is the best stuff is in newer versions of gcc (post 3.0) only.
#This works for even old (2.96) versions of gcc and provides a small boost either way.
#A ultrasparc cpu is really v9 but the stock debian stable 3.0 gcc doesn't support it.
#So we go lowest common available by gcc and go a step down, still a step up from
#the default as we now have a better instruction set to work with. - Belgarath
PROC=ultrasparc
OPTIONS+=$(shell if $(CC) -mtune=$(PROC) -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-mtune=$(PROC)"; fi)
OPTIONS+=$(shell if $(CC) -mcpu=v8 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-mcpu=v8"; fi)
OPTIONS+=-fomit-frame-pointer
endif

endif

ifeq (${OSARCH},Darwin)
SOLINK=-dynamic -bundle -undefined suppress -force_flat_namespace
else
SOLINK=-shared -Xlinker -x
endif
ifeq (${OSARCH},SunOS)
SOLINK=-shared -fpic -L$(CROSS_COMPILE_TARGET)/usr/local/ssl/lib
endif

ifeq (${OSARCH},FreeBSD)
OSVERSION=$(shell make -V OSVERSION -f /usr/share/mk/bsd.port.subdir.mk)
CFLAGS+=$(if ${OSVERSION}<500016,-D_THREAD_SAFE)
LIBS+=$(if ${OSVERSION}<502102,-lc_r,-pthread)
INCLUDE+=-I/usr/local/include
CFLAGS+=$(shell if [ -d /usr/local/include/spandsp ]; then echo "-I/usr/local/include/spandsp"; fi)
endif # FreeBSD

ifeq (${OSARCH},NetBSD)
CFLAGS+=-pthread
INCLUDE+=-I/usr/local/include
endif

ifeq (${OSARCH},OpenBSD)
CFLAGS+=-pthread
endif

#Tell gcc to optimize the asterisk's code
OPTIMIZE+=-O6

CFLAGS+=$(OPTIMIZE)
CFLAGS+= $(OPTIONS)

CC=gcc


format_mp3.so: $(MP3OBJS)
	$(CC) $(CFLAGS) $(SOLINK) -o $@ $(MP3OBJS)

all: $(MODS)

clean:
	rm -f *.o *.so *~

install: all
	$(INSTALL) -m 755 format_mp3.so $(DESTDIR)$(MODULES_DIR)

autoload: all
	asterisk -rx "unload format_mp3.so"
	$(INSTALL) -m 755 format_mp3.so $(DESTDIR)$(MODULES_DIR)
	asterisk -rx "load format_mp3.so"
