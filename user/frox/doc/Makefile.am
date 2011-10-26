man8_MANS = frox.man
man5_MANS = frox.conf.man
EXTRA_DIST = ChangeLog FAQ INSTALL INTERNALS CREDITS README.transdata RELEASE SECURITY TODO frox.man FAQ.sgml frox.sgml frox.conf.sgml frox.conf.man FAQ.html FAQ-1.html FAQ-2.html FAQ-3.html FAQ-4.html FAQ-5.html FAQ-6.html FAQ-7.html FAQ-8.html ccp-mirrors-example.c ccp-sizelimit-example.sh

all-local: FAQ.html FAQ frox.man frox.conf.man

FAQ.html: FAQ.sgml
	sgml2html -s 1 FAQ.sgml

FAQ: FAQ.sgml
	sgml2txt FAQ.sgml
	mv FAQ.txt FAQ

frox.man: frox.sgml
	sgml2txt -m frox.sgml

frox.conf.man: frox.conf.sgml
	sgml2txt -m frox.conf.sgml

distclean-local:
	rm -f FAQ FAQ.txt FAQ*html frox.man

