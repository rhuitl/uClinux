all:
	@echo Nothing to compile, just run \'make install\'
	@echo \(This simply copies this directory into $(PREFIX)/etc/l7-protocols \)	
install:
	mkdir -p $(PREFIX)/etc/l7-protocols
	cp -R * $(PREFIX)/etc/l7-protocols

romfs:
	[ -d $(ROMFSDIR)/etc/l7-protocols ] || mkdir -p $(ROMFSDIR)/etc/l7-protocols
	$(ROMFSINST) extra /etc/l7-protocols/extra
	$(ROMFSINST) file_types /etc/l7-protocols/file_types
	$(ROMFSINST) malware /etc/l7-protocols/malware
	$(ROMFSINST) protocols /etc/l7-protocols/protocols
