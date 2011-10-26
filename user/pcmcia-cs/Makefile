
all clean romfs:
	$(MAKE) -f Makefile.uClinux $@

ifdef NOT_DEF
#
# Makefile 1.39 2000/02/14 22:16:30 (David Hinds)
#

ifeq (config.mk, $(wildcard config.mk))
include config.mk
endif

ALL  = modules clients wireless cardmgr flash debug-tools man etc
DIRS = cardmgr flash debug-tools man etc
ifndef CONFIG_PCMCIA
DIRS := modules clients wireless $(DIRS)
endif

help:
	@echo "Pick one of the following targets:"
	@echo -e "\tmake config\t\t- configure and check system setup"
	@echo -e "\tmake oldconfig\t\t- reconfigure without prompting"
	@echo -e "\tmake all\t\t- build modules and programs"
	@echo -e "\tmake install\t\t- install modules and programs"
	@echo -e "\tmake clean\t\t- remove old binaries and dependency files"

config .prereq.ok:
	@touch config.mk
	@$(MAKE) -s clean
	@./Configure

oldconfig:
	@touch config.mk
	@$(MAKE) -s clean
	@./Configure -n

all:	.prereq.ok kcheck
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d ; done
	@for f in *.mk ; do \
	    if [ $$f != config.mk -a $$f != rules.mk ] ; then \
	    $(MAKE) -f $$f all ; \
	fi ; done

clean:
	@touch config.mk
	@set -e ; for d in $(ALL) ; do $(MAKE) -C $$d clean ; done
	rm -f .prereq.ok config.mk include/pcmcia/config.h
	rm -f include/linux/modversions.h

install: .prereq.ok kcheck
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d install ; done
	@for f in *.mk ; do \
	    if [ $$f != config.mk -a $$f != rules.mk ] ; then \
	    $(MAKE) -f $$f install ; \
	fi ; done

kcheck:
	@. ./config.out ; \
	if [ "$$CHECK" != "" ] ; then \
	    if [ "`cksum < $$CHECK`" != "$$CKSUM" ] ; then \
		/bin/echo -n "Kernel configuration has changed." ; \
		/bin/echo "  Please re-run 'make config'." ; \
		exit 1 ; \
	    fi ; \
	fi
endif
