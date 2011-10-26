all:
	$(MAKE) -C modules MODULES=hostap_cs.o
	$(MAKE) -C modules MODULES=hostap.o
	$(MAKE) -C modules MODULES=hostap_crypt_wep.o

install:
	$(MAKE) -C modules install-modules MODULES=hostap_cs.o
	$(MAKE) -C modules install-modules MODULES=hostap.o
	$(MAKE) -C modules install-modules MODULES=hostap_crypt_wep.o
