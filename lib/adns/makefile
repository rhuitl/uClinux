#
# Build using configure.
#

all: build/config.cache
	$(MAKE) MAKE="$(MAKE) -f Makefile"

romfs: build/config.cache
	#$(MAKE) MAKE="$(MAKE) -f Makefile " $@

build/config.cache: makefile
#	export CFLAGS="$(VENDOR_CFLAGS) -DEMBED -O2"; \
	unset LDFLAGS; 
	./configure

#	chmod u+x configure; \
	mkdir build; \
	cd build; 


clean:
	-rm -f dynamic/libadns.so.1.0
	-rm -f client/adnshost
	find ./ -name "*.o" | env -u xargs rm -Rf

