man_MANS = potrace.1 mkbitmap.1

EPSFILES = potracelib-fig1a.eps potracelib-fig1b.eps			\
 potracelib-fig2.eps potracelib-fig3.eps potracelib-fig4a.eps		\
 potracelib-fig4b.eps potracelib-fig5.eps potracelib-fig6a.eps		\
 potracelib-fig6b.eps potracelib-fig7-00.eps potracelib-fig7-06.eps	\
 potracelib-fig7-10.eps potracelib-fig7-12.eps potracelib-fig7-13.eps	\
 potracelib-fig8.eps

EXTRA_DIST = ${EPSFILES} potracelib.tex

potracelib.dvi: ${EPSFILES} potracelib.tex
	latex potracelib.tex
	latex potracelib.tex

potracelib-1up.ps: potracelib.dvi ${EPSFILES}
	dvips potracelib.dvi -o potracelib-1up.ps

potracelib.ps: potracelib-1up.ps
	pstops '2:0@0.94L(9.16in,-1.12in)+1@0.94L(9.16in,4.07in)' potracelib-1up.ps potracelib.ps

potracelib.pdf: potracelib.ps
	ps2pdf potracelib.ps

