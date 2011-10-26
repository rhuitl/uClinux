SOURCES = boa.sgml

OBJS = boa.html boa.dvi boa.ps boa.txt

all:	${OBJS}

boa.dvi:	${SOURCES}
	sgml2latex --output=dvi ${SOURCES}

boa.ps:	boa.dvi
	dvips -t letter boa.dvi -o boa.ps

boa.html:	${SOURCES} 
	sgml2html ${SOURCES}

boa.txt:	${SOURCES}
	sgml2txt --filter ${SOURCES}

clean:
	rm -f ${OBJS} boa-*.html
