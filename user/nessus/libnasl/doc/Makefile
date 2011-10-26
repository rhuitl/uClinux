include ../nasl.tmpl
docdir= ${datadir}/doc/libnasl

all: nasl_guide.ps


# Only works with GNU make, IIRC
%.pdf:	%.tex
	cat $< | perl fixtex.pl | pdflatex 
	mv texput.pdf $@

nasl_guide.ps : nasl_guide.dvi
	dvips nasl_guide.dvi -o nasl_guide.ps


nasl_guide.dvi : nasl_guide.tex nasl_guide.toc
	latex nasl_guide.tex

nasl_guide.toc : nasl_guide.tex
	latex nasl_guide.tex

nasl2_reference.tex:	nasl2_reference.lyx
	lyx -e latex nasl2_reference.lyx

nasl2_reference.dvi:	nasl2_reference.tex
	latex nasl2_reference.tex

nasl2_reference.pdf:	nasl2_reference.tex

nasl2_reference.ps:	nasl2_reference.dvi
	dvips nasl2_reference.dvi -o nasl2_reference.ps

nasl2_reference.html:	nasl2_reference.tex
	latex2html -split 0 -nosubdir nasl2_reference.tex

nasl2_reference.rtf:	nasl2_reference.tex
	latex2rtf -C latin1 -l nasl2_reference.tex

install: all
	test -d ${docdir} || $(INSTALL_DIR) -m 755 ${docdir}
	$(INSTALL) -m 644 nasl_guide.ps ${docdir}/

clean:
	rm -rf *.aux *.toc *.dvi *.ps *.log 

distclean: clean
