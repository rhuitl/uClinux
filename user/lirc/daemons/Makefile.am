## $Id: Makefile.am,v 5.17 2001/02/18 16:44:54 columbus Exp $

## Process this file with automake to produce Makefile.in 

## these are used by programs in the tools directory, but not by
## programs in this directory.  So we must make sure they get distributed

EXTRA_DIST = dump_config.c dump_config.h

sbin_PROGRAMS = lircd lircmd

lircd_SOURCES = lircd.c ir_remote.c config_file.c \
		lircd.h ir_remote.h config_file.h \
		hardware.h
lircd_LDADD = @hw_module@ @irman_lib@ @caraca_lib@ @daemon@
lircd_DEPENDENCIES = @hw_module@
EXTRA_lircd_SOURCES = hw_default.c hw_default.h \
			hw_pixelview.c hw_pixelview.h \
			hw_pinsys.c hw_pinsys.h \
			hw_logitech.c hw_logitech.h \
			hw_slinke.c hw_slinke.h \
			hw_irman.c hw_irman.h \
			hw_creative.c hw_creative.h \
			hw_silitek.c hw_silitek.h \
			receive.c receive.h \
			transmit.c transmit.h \
			serial.c serial.h

lircmd_SOURCES = lircmd.c
lircmd_LDADD = @daemon@

bin_PROGRAMS = irrecord

irrecord_SOURCES = irrecord.c dump_config.c dump_config.h \
		config_file.c config_file.h hardware.h \
		ir_remote.c ir_remote.h
irrecord_LDADD = @hw_module@ @irman_lib@ @caraca_lib@
irrecord_DEPENDENCIES = @hw_module@
EXTRA_irrecord_SOURCES = hw_default.c hw_default.h \
			hw_pixelview.c hw_pixelview.h \
			hw_pinsys.c hw_pinsys.h \
			hw_logitech.c hw_logitech.h \
			hw_slinke.c hw_slinke.h \
			hw_irman.c hw_irman.h \
			hw_creative.c hw_creative.h \
			hw_silitek.c hw_silitek.h \
			receive.c receive.h \
			transmit.c transmit.h \
			serial.c serial.h

## maintainer mode stuff
EXTRA_PROGRAMS = lircd.simsend lircd.simrec slinke
noinst_PROGRAMS = @maintmode_daemons_extra@
lircd_simsend_SOURCES = 
lircd_simsend_LDADD = lircd_simsend.o hw_default_simsend.o config_file.o \
			ir_remote.o receive.o transmit.o
lircd_simsend.o: lircd.c lircd.h ir_remote.h config_file.h hardware.h  $(top_srcdir)/config.h
	$(COMPILE) -DSIM_SEND -c lircd.c -o lircd_simsend.o
hw_default_simsend.o: hw_default.c hw_default.h hardware.h ir_remote.h lircd.h  $(top_srcdir)/config.h
	$(COMPILE) -DSIM_SEND -c hw_default.c -o hw_default_simsend.o
lircd_simrec_SOURCES = 
lircd_simrec_LDADD = lircd_simrec.o hw_default_simrec.o config_file.o \
			ir_remote.o receive.o transmit.o
lircd_simrec.o: lircd.c lircd.h ir_remote.h config_file.h hardware.h  $(top_srcdir)/config.h
	$(COMPILE) -DSIM_REC -c lircd.c -o lircd_simrec.o
hw_default_simrec.o: hw_default.c hw_default.h hardware.h ir_remote.h lircd.h  $(top_srcdir)/config.h
	$(COMPILE) -DSIM_REC -c hw_default.c -o hw_default_simrec.o

slinke_SOURCES = slinke.c slinke.h config_file.c config_file.h ir_remote.h \
		dump_config.c dump_config.h

install-exec-local: mkdev
uninstall-local: rmdev

install-data-local:
	test "$(lircd_conf)" = ""  || test -e $(sysconfdir)/lircd.conf  || ($(mkinstalldirs) $(sysconfdir) && $(INSTALL_DATA) $(top_srcdir)/remotes/$(lircd_conf) $(sysconfdir)/lircd.conf)
	test "$(lircmd_conf)" = "" || test -e $(sysconfdir)/lircmd.conf || ($(mkinstalldirs) $(sysconfdir) && $(INSTALL_DATA) $(top_srcdir)/remotes/$(lircmd_conf) $(sysconfdir)/lircmd.conf)

mkdev:
	test -e @devdir@/lircd || @mknod@ @devdir@/lircd p
	test -e @devdir@/lircm || @mknod@ @devdir@/lircm p

rmdev:
	$(RM) @devdir@/lircd
	$(RM) @devdir@/lircm

CLEANFILES = *~
