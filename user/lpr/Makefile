.EXPORT_ALL_VARIABLES:

DIRS = lpc lpd lpq lpr lprm
       #lptest pac filters

CFLAGS += -D_GNU_SOURCE -D__KAME__ -I../common_source
CPPFLAGS += -D_GNU_SOURCE -D__KAME__ -I../common_source

all:
	for i in $(DIRS) ; do make -C $$i || exit $? ; done

romfs:
	$(ROMFSINST) lpc/lpc /bin/lpc
	$(ROMFSINST) lpd/lpd /bin/lpd
	$(ROMFSINST) lpq/lpq /bin/lpq
	$(ROMFSINST) lpr/lpr /bin/lpr
	$(ROMFSINST) lprm/lprm /bin/lprm

clean:
	-for i in $(DIRS) ; do make -C $$i clean ; done
	-rm -f common_source/*.o
