###########################################################################
##
## Copyright (c) 2000-2003 Intel Corporation 
## All rights reserved. 
##
## Redistribution and use in source and binary forms, with or without 
## modification, are permitted provided that the following conditions are met: 
##
## * Redistributions of source code must retain the above copyright notice, 
## this list of conditions and the following disclaimer. 
## * Redistributions in binary form must reproduce the above copyright notice, 
## this list of conditions and the following disclaimer in the documentation 
## and/or other materials provided with the distribution. 
## * Neither name of Intel Corporation nor the names of its contributors 
## may be used to endorse or promote products derived from this software 
## without specific prior written permission.
## 
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
## ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
## LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
## A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR 
## CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
## EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
## PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
## PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
## OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
## NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
## SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##
###########################################################################

ifdef NOT_DEFINED
ifdef TARGET
DIR_PATH=$(TARGET)/
CROSS=$(TARGET)-

CC=$(CROSS)gcc
AR=$(CROSS)ar
LD=$(CROSS)ld
STRIP=$(CROSS)strip
endif
endif

ifndef DEBUG
export DEBUG = 0
endif

all:
	@if [ ! -d bin ] ; then mkdir -p bin ; fi
	@$(MAKE) DEBUG=$(DEBUG) -C ./src 

doc: html pdf

html:
	@if [ ! -d doc ]; then mkdir doc; fi
	@if [ -d doc/html ]; then rm -rf doc/html; fi
	@cd doc; doc++ -nd -S -w -j -d ../doc/html ixml.dxx

pdf:
	@if [ ! -d doc ]; then mkdir doc; fi
	@cd doc; doc++ -nd -S -w -j -t --package a4wide -o ixml.tex ixml.dxx
	@-cd doc; pdflatex "\scrollmode\input ixml.tex" > pdflatex.log
	@-cd doc; pdflatex "\scrollmode\input ixml.tex" >> pdflatex.log
	@-cd doc; pdflatex "\scrollmode\input ixml.tex" >> pdflatex.log

install:
	@$(MAKE) install -C ./src

uninstall:
	@$(MAKE) uninstall -C ./src

clean:
	@if [ -d bin ] ; then  rm -rf bin ; fi
	@if [ -d doc/html ]; then rm -rf doc/html; fi
	@if [ -f "doc/ixml.tex"     ]; then rm -f doc/ixml.tex; fi
	@if [ -f "doc/pdflatex.log" ]; then rm -f doc/pdflatex.log; fi
	@if [ -f "doc/ixml.log"     ]; then rm -f doc/ixml.log; fi
	@if [ -f "doc/ixml.aux"     ]; then rm -f doc/ixml.aux; fi
	@$(MAKE) clean -C ./src
