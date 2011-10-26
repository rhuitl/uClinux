#
# Makefile for mgetty/frontends/tkperl
#
all: faxman xfax

faxman: faxman.in ../../sedscript
	../../sedscript <faxman.in >faxman

xfax: xfax.in ../../sedscript
	../../sedscript <xfax.in >xfax

../../sedscript: ../../Makefile ../../policy.h ../../mksed.c
	@cd ..; $(MAKE) sedscript

install:
# scripts
	$(INSTALL) -m 755 faxman $(BINDIR)
	$(INSTALL) -m 755 xfax $(BINDIR)
# common subroutines / modules
	$(INSTALL) -m 644 FileSelector.pm $(LIBDIR)
	$(INSTALL) -m 644 XYListbox.pm $(LIBDIR)
	$(INSTALL) -m 644 handle_commands.pl $(LIBDIR)

