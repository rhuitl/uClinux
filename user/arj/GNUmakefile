CONFOPTS=--bindir=/bin --datadir=/etc 

all: Makefile.gnu
	MAKE="$(MAKE) -f Makefile.gnu" $(MAKE) -f Makefile.gnu

Makefile.gnu: gnu/configure
	@chmod u+x gnu/configure
	(cd gnu; sh configure $(CONFIGURE_OPTS) $(CONFOPTS))

gnu/configure: gnu/configure.in
	(cd gnu; autoheader; autoconf)

clean:
	if test -f Makefile.gnu; then $(MAKE) -f Makefile.gnu clean; fi
	rm -rf linux-gnu Makefile.gnu

romfs:
	$(MAKE) -f Makefile.gnu romfs
