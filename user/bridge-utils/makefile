CONFOPTS=--with-linux-headers=$(ROOTDIR)/$(LINUXDIR)/include

all: Makefile
	$(MAKE) -f Makefile

Makefile:
	sh configure $(CONFIGURE_OPTS) $(CONFOPTS)

clean:
	$(MAKE) -f Makefile maintainer-clean

romfs:
	$(ROMFSINST) brctl/brctl /bin/brctl
