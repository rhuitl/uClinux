#
# man/Makefile 1.49 2000/12/11 01:51:52 (David Hinds)
#

# Include site dependent options
include ../config.mk

COFLAGS = -kv
MANDIR := $(PREFIX)$(MANDIR)
XMANDIR := $(PREFIX)$(XMANDIR)

MAN1_X11 = cardinfo.1
MAN4 = pcmcia_core.4 tcic.4 i82365.4 tc589_cs.4 pcnet_cs.4 dummy_cs.4 \
	serial_cs.4 ftl_cs.4 memory_cs.4 fmvj18x_cs.4 tc574_cs.4 \
	tc575_cb.4 netwave_cs.4 wavelan_cs.4 aha152x_cs.4 xirc2ps_cs.4 \
	memory_cb.4 ibmtr_cs.4 smc91c92_cs.4 iflash2_mtd.4 iflash2+_mtd.4 \
	wvlan_cs.4 ray_cs.4 airo.4 airo_cs.4
MAN5 = pcmcia.5 stab.5
MAN8 = cardmgr.8 cardctl.8 ftl_format.8 ftl_check.8 scsi_info.8 \
	ifport.8 ifuser.8 ide_info.8 pcinitrd.8 pack_cis.8 dump_cis.8 \
	lspnp.8 setpnp.8

all: $(MAN1_X11) $(MAN4) $(MAN5) $(MAN8)

dep:

clean:

install-man1-x11: $(MAN1_X11)
	@mkdir -p $(XMANDIR)/man1
	cp $(MAN1_X11) $(XMANDIR)/man1

install-man4: $(MAN4)
	@mkdir -p $(MANDIR)/man4
	cp *.4 $(MANDIR)/man4

install-man5: $(MAN5)
	@mkdir -p $(MANDIR)/man5
	cp *.5 $(MANDIR)/man5

install-man8: $(MAN8)
	@mkdir -p $(MANDIR)/man8
	cp *.8 $(MANDIR)/man8

install: install-man1-x11 install-man4 install-man5 install-man8

man2html: $(MAN1) $(MAN4) $(MAN5) $(MAN8)
	for f in *.[1458] ; do				\
	    man2html $$f | ./fixhtml > html/$$f.html ;	\
	done
	./indexhtml > html/index.html
