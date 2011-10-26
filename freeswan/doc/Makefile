# Makefile to generate various formats from HTML source
#
# Assumes the htmldoc utility is available.
# This can be downloaded from www.easysw.com
#
# Also needs lynx(1) for HTML-to-text conversion

# Format arguments for htmldoc
F="--toclevels 4 --header 1cd"

# source files in subdirectory
# basic stuff
a=src/intro.html src/quickstart.html src/faq.html
# related
b=src/manpages.html src/firewall.html src/trouble.html
# more advanced
c=src/compat.html src/interop.html src/performance.html \
	src/testing.html src/kernel.html src/adv_config.html \
	src/install.html src/config.html \
	src/background.html src/user_examples.html
# background and reference material
d=src/politics.html src/ipsec.html \
	src/mail.html src/web.html src/glossary.html src/biblio.html \
	src/rfc.html src/roadmap.html
sections=$a $b $c $d

# separate HTML files built in current directory
separate=intro.html install.html config.html manpages.html \
	firewall.html trouble.html kernel.html roadmap.html \
	compat.html interop.html politics.html ipsec.html \
	mail.html performance.html testing.html web.html \
	glossary.html biblio.html rfc.html faq.html \
	adv_config.html user_examples.html background.html \
	quickstart.html

# various one-big-file formats
howto=HowTo.html HowTo.ps HowTo.pdf HowTo.txt

# where are scripts
SCRIPTDIR=utils

# where do we put HTML manpages?
HMANDIR=manpage.d

# which sort of manpage conversion do we do?
MCT=$(test " `which man2html`" != " /usr/bin/man2html" && echo .old)

# default, build HTML only
# dependencies build most of it
# then we add index
index.html: toc.html HowTo.html manpages src/index.html
	cp src/index.html index.html

# separate files plus table of contents
toc.html : $(sections)
	htmldoc -t html -d .  $(sections)
	# remove HTML formatting added by htmldoc
	$(SCRIPTDIR)/cleanhtml.sh $(SCRIPTDIR)/cleanhtml.sed $(separate)

# one big HTML file
HowTo.html : $(sections)
	htmldoc -t html --toclevels 4 --header ' cf' -f $@ $(sections)

# other HowTo formats
HowTo.txt: HowTo.html
	lynx -dump $< > $@

HowTo.ps : $(sections)
	htmldoc -f $@ $(sections)

HowTo.pdf : $(sections)
	htmldoc -f $@ $(sections)

manpages:	manp$(MCT)

manp:	$(SCRIPTDIR)/mkhtmlman
	$(SCRIPTDIR)/mkhtmlman $(HMANDIR) `find .. -type f -name '*.[1-8]'`

manp.old:	$(SCRIPTDIR)/man_xref
	$(SCRIPTDIR)/man2html.script /usr/local/man $(HMANDIR)

programs: 

all: $(howto) $(manpages) index.html

clean:
	rm -f $(howto) $(separate) toc.html index.html
	rm -rf $(HMANDIR)

checkprograms:

# not enabled by default, because xml2rfc must be installed first.
drafts: draft-richardson-ipsec-opportunistic.txt src/draft-richardson-ipsec-opportunistic.html

draft-richardson-ipsec-opportunistic.txt: src/draft-richardson-ipsec-opportunistic.xml
	XML_LIBRARY=$(XML_LIBRARY):./src xml2rfc xml2rfc $? $@

src/draft-richardson-ipsec-opportunistic.html: src/draft-richardson-ipsec-opportunistic.xml
	XML_LIBRARY=$(XML_LIBRARY):./src xml2rfc xml2html $? $@

