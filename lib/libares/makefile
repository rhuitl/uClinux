CONFOPTS := 

all: build/build
	$(MAKE) -C build
	$(RANLIB) build/libares.a

build/build: makefile
	@chmod u+x configure
	@rm -rf build
	@mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	@touch build/build

clean:
	rm -rf build

romfs:
