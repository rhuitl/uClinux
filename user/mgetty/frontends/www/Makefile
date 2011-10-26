# frontends/www/Makefile
#
# RCS: $Id: Makefile,v 1.15 2004/11/17 15:40:57 gert Exp $
#
# $Log: Makefile,v $
# Revision 1.15  2004/11/17 15:40:57  gert
# create install directories if not present yet
#
# Revision 1.14  2004/11/17 15:07:50  gert
# adapt path names to current MEDAT system (D3.0)
# install *.gif images (if not yet installed)
#
# Revision 1.13  1998/12/04 15:56:44  gert
# faxsend added
#
# Revision 1.12  1998/11/24 16:25:43  gert
# add faxhists.in/cgi
#
# Revision 1.11  1998/11/22 10:16:14  gert
# add dependencies for index-e.html
#
# Revision 1.10  1998/11/22 10:13:35  gert
# fix sed/@CGI_HREF@ for empty definition
#
# Revision 1.9  1998/10/27 12:37:27  gert
# new index page (english)
#
# Revision 1.8  1998/10/22 12:55:22  gert
# add (first cut) 'make install' support
#
#...
# Revision 1.1  1998/08/28 14:25:24  gert
# initial release
#

CGI=faxq.cgi faxq-v.cgi faxhist.cgi faxhists.cgi \
		viewfax.cgi nph-vf-gif.cgi faxsend.cgi
HTML=index-d.html index-e.html
IMAGES=delete.gif pfeild.gif pfeill.gif pfeilr.gif

# the directory for the HTML file(s)
# leave empty if you do not want to install the HTML files
HTMLDIR=/david/html/quickfax/

# the directory for the sample image files (left/right arrows, logo, ...)
# (whether this is the same as HTMLDIR or not depends on local preferences,
#  but don't forget to adapt the http path name in wwwgui.conf accordingly)
IMAGEDIR=/stf/html/images/

# this is the directory the CGI binaries will be installed in
# check with your local webmaster or the WWW server documentation!
CGIBINDIR=/david/html/quickfax/cgi-bin/

# this is the logical path from the WWW root to the CGI binaries
# (if the CGI binaries are in the same directory as "index.html", just
# leave it empty: CGI_HREF="")
CGI_HREF=/cgi-bin/
# CGI_HREF=""

all: $(CGI) $(HTML) wwwgui.conf

clean:
	rm -f $(CGI)
	rm -f $(HTML)
	rm -f wwwgui.conf

fullclean: clean

# install from here is ugly, 'cause we have to go "up" to get LIBDIR etc.
install: all
	@echo "automatic installation largely untested - expect problems"
	sleep 5
	cd ../.. ; $(MAKE) install.www

install.www:
	test -d $(CGIBINDIR) || \
		mkdir -p $(CGIBINDIR)
	test -d $(IMAGEDIR) || \
		mkdir -p $(IMAGEDIR)
	test -d $(HTMLDIR) || \
		mkdir -p $(HTMLDIR)
	-@for i in $(CGI); do \
		echo "$$i -> $(CGIBINDIR)..." ; \
		mv -f $(CGIBINDIR)/$$i $(CGIBINDIR)/$$i.old 2>/dev/null ; \
		$(INSTALL) -m 755 $$i $(CGIBINDIR) ; \
	done
	-@for i in $(IMAGES); do \
		echo "$$i -> $(IMAGEDIR)..." ; \
		test -f $(IMAGEDIR)/$$i || \
		    $(INSTALL) -m 644 $$i $(IMAGEDIR) ; \
	done 
	test -z "$(HTMLDIR)" || \
	    for i in $(HTML); do \
		test -f $(HTMLDIR)/$$i || \
		    $(INSTALL) -m 644 $$i $(HTMLDIR) ; \
	    done
	test -f $(CONFDIR)/wwwgui.conf || \
		$(INSTALL) -o root -m 644 wwwgui.conf $(CONFDIR)/
	$(INSTALL) -m 755 simplequant.pl $(LIBDIR)/
	$(INSTALL) -m 755 wwwsub.pl $(LIBDIR)/

# explicit dependencies

faxq.cgi: faxq.in ../../sedscript
faxq-v.cgi: faxq-v.in ../../sedscript
index-d.html: index-d.in ../../sedscript Makefile
index-e.html: index-e.in ../../sedscript Makefile
faxhist.cgi: faxhist.in ../../sedscript
faxhists.cgi: faxhists.in ../../sedscript
viewfax.cgi: viewfax.in ../../sedscript
nph-vf-gif.cgi: nph-vf-gif.in ../../sedscript
vf-faxov.cgi: vf-faxov.in ../../sedscript
service.cgi: service.in ../../sedscript
faxsend.cgi: faxsend.in ../../sedscript

wwwgui.conf: wwwgui.cfg.in ../../sedscript
	../../sedscript <wwwgui.cfg.in >wwwgui.conf

../../sedscript: ../../policy.h ../../Makefile ../../mksed.c
	@cd ../.. ; $(MAKE) sedscript

#
# inference rules for creating CGI binaries / HTML pages from *.in files
#
.SUFFIXES: .in .cgi .html

.in.cgi:
	rm -f $*.cgi
	../../sedscript <$< >$*.cgi
	chmod +x $*.cgi

.in.html:
	rm -f $*.html
	../../sedscript <$< | \
		sed -e "s!@CGI_HREF@!$(CGI_HREF)!" >$*.html

