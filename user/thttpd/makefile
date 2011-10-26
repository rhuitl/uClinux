ifneq (,$(CONFIG_READ_TIMEOUT)$(READ_TIMEOUT))
CFLAGS += -DCONFIG_READ_TIMEOUT
endif

CONFOPTS =

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/thttpd /bin/thttpd

