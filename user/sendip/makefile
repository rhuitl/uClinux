
all:
	$(MAKE) -f Makefile CC="$(CC)" PREFIX="/"

clean:
	$(MAKE) -f Makefile clean

romfs:
	mkdir -p $(ROMFSDIR)/lib/sendip
	$(ROMFSINST) /bin/sendip
	@for i in *.so; do \
		echo "$(ROMFSINST) /lib/sendip/$$i"; \
		$(ROMFSINST) /lib/sendip/$$i; \
	done
