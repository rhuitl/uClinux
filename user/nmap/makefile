#
# build nmap in a subdir
#

CONFOPTS =	--without-nmapfe		\
		--with-pcap=linux		\
		--datadir=/etc

CXXFLAGS    += -I$(STL_INCDIR) 

all: build/build
	$(MAKE) -C build

build/build: makefile
	@chmod u+x configure
	@rm -rf build
	@mkdir build
	find . -type d > .dirs
	find . ! -type d | grep -v ./makefile > .files
	while read t; do mkdir -p build/$$t; done < .dirs
	while read t; do ln -s `pwd`/$$t build/$$t; done < .files
	rm -f .dirs .files
	(cd build; CXXPROG="UNUSED" sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	@touch build/build

clean:
	-rm -rf build

romfs:
	[ -d $(ROMFSDIR)/etc/nmap ] || mkdir $(ROMFSDIR)/etc/nmap
	$(ROMFSINST) build/nmap			/bin/nmap
	$(ROMFSINST) nmap-services		/etc/nmap
	$(ROMFSINST) nmap-rpc			/etc/nmap
	$(ROMFSINST) nmap-os-db			/etc/nmap
	$(ROMFSINST) nmap-protocols		/etc/nmap
	$(ROMFSINST) nmap-mac-prefixes		/etc/nmap
	$(ROMFSINST) nmap-os-fingerprints	/etc/nmap
	$(ROMFSINST) nmap-service-probes	/etc/nmap


