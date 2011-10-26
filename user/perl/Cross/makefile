
all: .setup
	$(MAKE) -f Makefile perl

.setup:
	cp config.cross config.cross.$$
	if [ "$(ENDIAN)" = "big" ]; then \
		echo "PERL: building for big endian" ; \
		sed -e "s/byteorder='1234'/byteorder='4321'/g" config.cross.$$ > config.cross ; \
	else \
		echo "PERL: building for little endian" ; \
		sed -e "s/byteorder='4321'/byteorder='1234'/g" config.cross.$$ > config.cross ; \
	fi
	rm config.cross.$$
	> .setup

clean:
	rm -f .setup
	$(MAKE) -f Makefile clean

romfs:
	$(ROMFSINST) ../miniperl /usr/bin/perl

