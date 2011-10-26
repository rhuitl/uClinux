.SUFFIXES: .ps .fig .dvi .aux .html .eps

PROJECT=klips2req
TOP=klips2req
TEXFILES=klips2req.tex macros.tex requirements/requirements.tex 
TEXFILES+=klips1structure.tex klips2structure.tex
FIGFILES=diagrams/klips2_flow.fig
DIAFILES=diagrams/klips1_tdb.dia
PSFILES=${FIGFILES:S/.fig/.eps/} ${DIAFILES:S/.dia/.eps/}
HTMLDIR=/corp/docs/SSW/freeswan/klips2req
HTMLTOP=${HTMLDIR}/${TOP}.html

all: ${PROJECT}.ps ${HTMLTOP} ${PROJECT}.pdf

${HTMLTOP}: ${TEXFILES} ${PSFILES}
	-mkdir -p ${HTMLDIR}
	latex2html -info 0 -show_section_numbers -long_titles 4 -dir ${HTMLDIR} ${TOP}.tex

${PROJECT}.pdf: ${PROJECT}.ps
	ps2pdf ${PROJECT}.ps
	cp ${PROJECT}.pdf ${HTMLDIR}

${PROJECT}.ps : $(PSFILES) ${TOP}.dvi
	dvips -o ${PROJECT}.ps ${TOP}
	-mkdir -p ${HTMLDIR}
	echo cp ${PROJECT}.ps ${HTMLDIR}

${PROJECT}.g3: ${PROJECT.ps 
	gs -sDEVICE=faxg3 -sOutputFile=${PROJECT}.g3 ${PROJECT}.ps quit.ps

${TOP}.dvi : ${TEXFILES}
	latex ${TOP} || rm ${TOP}.dvi
	touch ${TOP}.aux-old
	if cmp -s ${TOP}.aux ${TOP}.aux-old ;\
        then \
          echo references are correct; \
        else  \
	  bibtex ${TOP} || exit 0;\
          cp ${TOP}.aux ${TOP}.aux-old; \
          latex ${TOP}; \
        fi

${TOP}.bbl : ${TOP}.bib
	latex ${TOP}
	bibtex ${TOP}

clean : 
	-rm -f ${TOP}.aux ${TOP}.bbl ${TOP}.dvi ${TOP}.aux-old ${TOP}.log *.ps 

.fig.eps: 
	fig2dev -L ps $< >$@

.fig.ps: 
	fig2dev -L ps -P $< >$@


