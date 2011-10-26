
BINDIR=src/bin

all clean:
	[ -d src/lib ] || mkdir src/lib
	[ -d src/bin ] || mkdir src/bin
	$(MAKE) -C src TOOLSPREFIX=$(CROSS_COMPILE) $@ || exit 1

romfs:
	$(MAKE) -C src/bin -f ../../Makefile real_romfs || exit 1

real_romfs:
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_LANDMINE    /bin/landmine
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_LAUNCHER    /bin/launcher
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_MOVE        /bin/move
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_MTERM       /bin/mterm
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_MTEST       /bin/mtest
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_MTEST2      /bin/mtest2
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_MUSERFD     /bin/muserfd
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NANO_X      /bin/nano-X
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NANOWM      /bin/nanowm
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NPANEL      /bin/npanel
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NTERM       /bin/nterm
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NTEST       /bin/ntest
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NTETRIS     /bin/ntetris
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NXCLOCK     /bin/nxclock
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NXEV        /bin/nxev
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NXKBD       /bin/nxkbd
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NXLSCLIENTS /bin/nxlsclients
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NXTERM      /bin/nxterm
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_NXVIEW      /bin/nxview
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_SLIDER      /bin/slider
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_VNC         /bin/vnc	
	$(ROMFSINST) -e CONFIG_USER_MICROWIN_BIN_WORLD       /bin/world
