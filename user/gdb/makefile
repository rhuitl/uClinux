CONFOPTS += --with-readline --disable-nls

ifdef CONFIG_USER_GDB_TARGET
	TARGETS += build/target
else
	ifdef CONFIG_USER_GDB_GDBSERVER
		TARGETS += build/build
	endif
	ifdef CONFIG_USER_GDB_GDBREPLAY
		TARGETS += build/build
	endif
endif
ifdef CONFIG_USER_GDB_HOST
	TARGETS += host/build
endif

all: $(TARGETS)
	$(MAKE) -C build
ifdef CONFIG_USER_GDB_HOST
	$(MAKE) -C host
	ln -sf $(ROOTDIR)/user/gdb/host/gdb/gdb $(ROOTDIR)/tools/$(ARCH)-gdb
endif

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../gdb/gdbserver/configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch $@

build/target: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS) )
	touch $@

host/build: makefile
	rm -rf host
	mkdir host
	(cd host; RANLIB=ranlib CC= CFLAGS= ../configure --host=$(HOSTARCH) --build=$(HOSTARCH) --target=$(TARGETARCH))
	touch $@

clean:
	rm -rf build host
ifdef CONFIG_USER_GDB_HOST
	rm -f ../../tools/$(ARCH)-gdb
endif

romfs:
ifdef CONFIG_USER_GDB_TARGET
	$(ROMFSINST) build/gdb/gdb /bin/gdb
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBSERVER build/gdb/gdbserver/gdbserver /bin/gdbserver
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBREPLAY build/gdb/gdbreplay/gdbreplay /bin/gdbreplay
else
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBSERVER build/gdbserver /bin/gdbserver
	$(ROMFSINST) -e CONFIG_USER_GDB_GDBREPLAY build/gdbreplay /bin/gdbreplay
endif
