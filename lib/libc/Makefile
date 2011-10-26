#
#	Makefile -- Master makefile for small libc
#

.EXPORT_ALL_VARIABLES:

SUBDIRS=error gtermcap misc stdio2 time getent regexp string termios \
        sysdeps malloc net rpc $(MACHINE) serial math
		# shm - doesn't work for 2.4 yet

ifdef CONFIG_BINFMT_SHARED_FLAT
 ifndef DISABLE_SHARED_LIBS
  # For the shared version of this, we specify no stack and its library ID
  FLTFLAGS += -s 0
  LIBID=1
  SHARED_TARGET = libc
 endif
endif

ifdef CONFIG_LIB_UC_LIBC_TIMEZONE
CFLAGS += -DINCLUDE_TIMEZONE
ifdef CONFIG_LIB_UC_LIBC_TZ_FROM_FILE
CFLAGS += -DTZ_FROM_FILE
endif
endif

CFLAGS += -I$(ROOTDIR)/lib/libc/include


all: headers subdirs .ranlib libg.a $(SHARED_TARGET)

.PHONY: subdirs
subdirs:
	for i in $(SUBDIRS); do make -C $$i all || exit 1; done

bogus $(SHARED_TARGET): libc.a main.o
	make -C $(ROOTDIR) relink
	$(CC) -o $(SHARED_TARGET) $(LDFLAGS)	-nostdlib		\
		-Wl,-shared-lib-id,${LIBID}				\
		main.o -Wl,--whole-archive,libc.a,-lgcc,--no-whole-archive
	$(OBJCOPY) -L _GLOBAL_OFFSET_TABLE_ -L main -L __main -L _start \
		-L __uClibc_main -L lib_main -L _exit_dummy_ref		\
		-L __do_global_dtors -L __do_global_ctors		\
		-L __CTOR_LIST__ -L __DTOR_LIST__			\
		-L _current_shared_library_a5_offset_			\
		$(SHARED_TARGET).gdb

libg.a: libc.a
	ln -f libc.a libg.a

.ranlib: libc.a
	$(RANLIB) libc.a
	touch .ranlib

.PHONY: headers
headers:
	#if [ ! -L "include/asm" ]; then \
	#	ln -s ../../../$(LINUXDIR)/include/asm include/asm ; \
	#fi
	#if [ ! -L "include/linux" ]; then \
	#	ln -s ../../../$(LINUXDIR)/include/linux include/linux ; \
	#fi
	if [ ! -L "include/machine" ]; then \
		ln -s $(MACHINE) include/machine ; \
	fi
	if [ ! -L "stdio2/stdio.h" ]; then \
		ln -s ../include/stdio.h stdio2/stdio.h ; \
	fi
	if [ ! -L "include/netinet/in_system.h" ]; then \
		ln -s in_systm.h include/netinet/in_system.h ; \
	fi

.PHONY: romfs
romfs:
	@if [ "$(SHARED_TARGET)" ]; then \
		[ -e $(ROMFSDIR)/lib ] || mkdir -p $(ROMFSDIR)/lib; \
		$(ROMFSINST) $(SHARED_TARGET) /lib/lib$(LIBID).so; \
	fi

.PHONY: clean
clean:
	-rm -f `find . -name \*.[oa] -o -name \*~` core
	-rm -f .ranlib include/asm include/linux
	-rm -f include/machine stdio2/stdio.h include/netinet/in_system.h
	-rm -f $(SHARED_TARGET) $(SHARED_TARGET).gdb

