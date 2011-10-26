
CONFOPTS=

all: build/configured
	$(MAKE) -C build

build/configured: makefile
	rm -rf build
	find . -type d > .dirs
	find . ! -type d | grep -v ./makefile > .files
	while read t; do mkdir -p build/$$t; done < .dirs
	while read t; do ln -s `pwd`/$$t build/$$t; done < .files
	rm -f .dirs .files
	chmod +x build/configure
	cd build; sh ./configure $(CONFIGURE_OPTS) $(CONFOPTS)
	touch build/configured

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_PPPD_PPPD_PPPD build/pppd/pppd /bin/pppd
	$(ROMFSINST) -e CONFIG_USER_CHAT_CHAT build/chat/chat /bin/chat
ifdef CONFIG_USER_PPPD_WITH_RADIUS
	[ -d $(ROMFSDIR)/etc/radiusclient ] || mkdir $(ROMFSDIR)/etc/radiusclient
	$(ROMFSINST) -e CONFIG_USER_PPPD_WITH_RADIUS scripts/radiusclient/dictionary /etc/radiusclient/dictionary
	$(ROMFSINST) -e CONFIG_USER_PPPD_WITH_RADIUS scripts/radiusclient/dictionary.ms /etc/radiusclient/dictionary.ms
	$(ROMFSINST) -e CONFIG_USER_PPPD_WITH_RADIUS scripts/radiusclient/dictionary.sg /etc/radiusclient/dictionary.sg
endif