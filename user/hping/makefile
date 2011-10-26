#
# build hping in a subdir
#

all: build/configured
	$(MAKE) -C build

build/configured: makefile configure.dist
	rm -rf build
	find . -type d > .dirs
	find . ! -type d | grep -v ./makefile > .files
	while read t; do mkdir -p build/$$t; done < .dirs
	while read t; do ln -s `pwd`/$$t build/$$t; done < .files
	rm -f .dirs .files
	chmod +x build/configure.dist
	cd build; rm -f .depend Makefile byteorder.h; ./configure.dist
	touch build/configured

clean:
	-rm -rf build

romfs:
	$(ROMFSINST) build/hping3 /bin/hping

