
.EXPORT_ALL_VARIABLES:

CFLAGS += -DHAVE_CONFIG_H
DIRS = daemons tools

all:
	for i in $(DIRS) ; do make -C $$i ; done

clean:
	-for i in $(DIRS) ; do make -C $$i clean ; done

romfs:
	$(ROMFSINST) daemons/lircd    /bin/lircd
	$(ROMFSINST) daemons/irrecord /bin/irrecord
	$(ROMFSINST) daemons/lircmd   /bin/lircmd
	$(ROMFSINST) tools/irexec     /bin/irexec
	$(ROMFSINST) tools/irw        /bin/irw
	$(ROMFSINST) tools/mode2      /bin/mode2
	touch $(ROMFSDIR)/dev/@lirc,c,61,0


