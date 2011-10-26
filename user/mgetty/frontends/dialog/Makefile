# Makefile for the "frontends/dialog" subtree
# of mgetty+sendfax
#
# SCCS: %W% %E% Copyright (c) Gert Doering
#

#DIALOG_SCRIPTS=faxv listen xfaxq
DIALOG_SCRIPTS=faxv xfaxq

all: $(DIALOG_SCRIPTS)

faxv: faxv.in ../../sedscript
	../../sedscript <faxv.in >faxv
	chmod 755 faxv

listen: listen.in ../../sedscript
	../../sedscript <listen.in >listen
	chmod 755 listen

xfaxq: xfaxq.in ../../sedscript
	../../sedscript <xfaxq.in >xfaxq
	../../sedscript <xfaxq.1in >xfaxq.1
	chmod 755 xfaxq

../../sedscript: ../../policy.h ../../Makefile ../../mksed.c
	@cd ../.. ; $(MAKE) sedscript

clean:
	-rm -f $(DIALOG_SCRIPTS)

fullclean:
	-rm -f $(DIALOG_SCRIPTS)

install: all
	-for i in $(DIALOG_SCRIPTS); do \
		mv -f $(BINDIR)/$$i $(BINDIR)/$$i.old 2>/dev/null ; \
		$(INSTALL) -m 775 $$i $(BINDIR) ; \
	done
