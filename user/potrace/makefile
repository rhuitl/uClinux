
CONFOPTS :=	--enable-a4

all: build/build
	$(MAKE) -C build

build/build: makefile
	@chmod u+x configure
	@rm -rf build
	@mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	@touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/src/potrace /bin/potrace
	$(ROMFSINST) build/src/potrace /bin/mkbitmap
