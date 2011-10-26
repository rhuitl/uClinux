#! /usr/bin/make
# this file is shamelessly stolen from the iptables CVS tree

LANG_DIRS:=

HOWTOS:=$(wildcard *.sgml)
HOWTOS+=$(foreach dir, $(LANG_DIRS), $(wildcard $(dir)/*.sgml))

TXT_HOWTOS:=$(HOWTOS:.sgml=.txt)
HTML_HOWTOS:=$(HOWTOS:.sgml=.html)
PSA4_HOWTOS:=$(HOWTOS:.sgml=.a4.ps)
PSUS_HOWTOS:=$(HOWTOS:.sgml=.letter.ps)

HOWTO_FLAGS_it/=-c latin -l it
HOWTO_FLAGS_fr/=-c latin -l fr

user_calls_make:

distrib: $(TXT_HOWTOS) $(PSA4_HOWTOS) $(HTML_HOWTOS)

HOWTOs: $(TXT_HOWTOS) $(HTML_HOWTOS) $(PSA4_HOWTOS) $(PSUS_HOWTOS)

# Remake all if Makefile changes.
$(TXT_HOWTOS) $(HTML_HOWTOS) $(PSA4_HOWTOS) $(PSUS_HOWTOS): Makefile

# Stupid sgml2* tools strip dirnames for output files. 8(
%.txt: %.sgml
	@echo Making $@: && cd `dirname $<` && sgml2txt --filter $(HOWTO_FLAGS_$(dir $<)) `basename $<` 2>&1 | sed "s?^<standard input>:\([0-9]*\):[^ ]* ?$<:\1:?"

%.a4.dvi: %.sgml
	@echo Making $@: && cd `dirname $<` && sgml2latex --papersize=a4 --output=dvi $(HOWTO_FLAGS_$(dir $<)) `basename $<` 2>&1 | sed "s?^<standard input>:\([0-9]*\):[^ ]* ?$<:\1:?" && mv `basename $*.dvi` `basename $*.a4.dvi`

%.a4.ps: %.a4.dvi
	@dvips -t a4 -o $@ $< 

%.letter.dvi: %.sgml
	@echo Making $@: && cd `dirname $<` && sgml2latex --papersize=letter --output=dvi $(HOWTO_FLAGS_$(dir $<)) `basename $<` 2>&1 | sed "s?^<standard input>:\([0-9]*\):[^ ]* ?$<:\1:?" && mv `basename $*.dvi` `basename $*.letter.dvi`

%.letter.ps: %.letter.dvi
	@dvips -t letter -o $@ $< 

%.html: %.sgml
	@echo Making $@: && cd `dirname $<` && sgml2html -s 0 $(HOWTO_FLAGS_$(dir $<)) `basename $<` 2>&1 | sed "s?^<standard input>:\([0-9]*\):[^ ]* ?$<:\1:?"

clean:
#	for d in . $(LANG_DIRS); do rm -f $$d/*.html $$d/*.ps $$d/*.aux $$d/*.log $$d/*.txt $$d/*~; done

distclean:
	rm -f Makefile

install:
