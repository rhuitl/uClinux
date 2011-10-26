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
else
CC = gcc
AR = ar
LD = ld
STRIP = strip
endif
endif

ifeq ($(DEBUG),1)
OUTPATH=bin/debug/$(DIR_PATH)
else
OUTPATH=bin/$(DIR_PATH)
endif

ifeq ($(STATIC),1)
UPNP=$(OUTPATH)libupnp.a
else
UPNP = $(OUTPATH)libupnp.so
endif

IXML_DIR = ../ixml
THREADUTIL_DIR = ../threadutil

SUBDIRS = src

VERSION=1.2.1

ifeq ($(INSURE),1)
STRIPU =
else
ifeq ($(DEBUG),1)
STRIPU =
else
STRIPU = $(STRIP) $(UPNP)
endif
endif

ifeq ($(STATIC),1)
STRIPU =
endif

ifndef DEBUG
export DEBUG=0
endif

ifndef WEB
export WEB=1
endif

ifndef TOOLS
export TOOLS=1
endif

ifndef CLIENT
export CLIENT=1
endif

ifndef DEVICE
export DEVICE=1
endif

ifeq ($(DEVICE),0)
export WEB=0
endif

ifndef JNI
export JNI=0
endif

all: upnp

upnp:
	@if [ ! -d bin ]; then mkdir bin; fi
	@if [ ! -d lib ]; then mkdir lib; fi
	@if [ ! -d $(OUTPATH) ]; then mkdir -p $(OUTPATH); fi
	@if [ ! -d src/lib ]; then mkdir src/lib; fi
	@$(MAKE) DEBUG=$(DEBUG) all -C $(IXML_DIR)
	@cp $(IXML_DIR)/inc/*.h ./inc

ifeq ($(DEBUG),1)
	@if [ -f $(IXML_DIR)/bin/debug/$(DIR_PATH)libixml.so ]; then \
          cp $(IXML_DIR)/bin/debug/$(DIR_PATH)libixml.so \
             ./bin/debug/$(DIR_PATH); \
        fi
else
	@if [ -f $(IXML_DIR)/bin/$(DIR_PATH)libixml.so ]; then \
          cp $(IXML_DIR)/bin/$(DIR_PATH)libixml.so ./bin/$(DIR_PATH); \
        fi
endif
	@$(MAKE) all DEBUG=$(DEBUG) all -C $(THREADUTIL_DIR)
	@cp $(THREADUTIL_DIR)/inc/*.h ./inc

ifeq ($(DEBUG),1)
	@if [ -f $(THREADUTIL_DIR)/bin/debug/$(DIR_PATH)libthreadutil_dbg.so ]; then \
          cp $(THREADUTIL_DIR)/bin/debug/$(DIR_PATH)libthreadutil_dbg.so \
             ./bin/debug/$(DIR_PATH); \
        fi
else
	@if [ -f $(THREADUTIL_DIR)/bin/$(DIR_PATH)libthreadutil.so ]; then \
          cp $(THREADUTIL_DIR)/bin/$(DIR_PATH)libthreadutil.so \
             ./bin/$(DIR_PATH); \
        fi
endif
	@$(MAKE) DEBUG=$(DEBUG) all -C src
	@$(STRIPU)

doc: html pdf

html:
	@if [ -d doc/html ]; then rm -rf doc/html; fi
	@cd doc; doc++ -nd -S -w -j -d html upnpsdk.dxx

pdf:
	@cd doc; doc++ -nd -S -w -j -t --package a4wide -o upnpsdk.tex upnpsdk.dxx
	@-cd doc; pdflatex "\scrollmode\input upnpsdk.tex" > latex.log
	@-cd doc; pdflatex "\scrollmode\input upnpsdk.tex" >> latex.log
	@-cd doc; pdflatex "\scrollmode\input upnpsdk.tex" >> latex.log
	@$(MAKE) pdf -C $(IXML_DIR)
	@cp $(IXML_DIR)/doc/*.pdf ./doc

clean:
	@set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	@if [ -d bin ]; then rm -rf bin; fi
	@-rm -f bin/Test
	@-rm -rf doc/html
	@if [ -f "doc/upnpsdk.tex" ]; then rm doc/upnpsdk.tex; fi
	@if [ -f "doc/upnpsdk.dvi" ]; then rm doc/upnpsdk.dvi; fi
	@if [ -f "doc/upnpsdk.ps"  ]; then rm doc/upnpsdk.ps; fi
	@if [ -f "doc/upnpsdk.log" ]; then rm doc/upnpsdk.log; fi
	@if [ -f "doc/upnpsdk.aux" ]; then rm doc/upnpsdk.aux; fi
	@if [ -f "doc/latex.log"   ]; then rm doc/latex.log; fi
	@$(MAKE) -C $(IXML_DIR) clean
	@$(MAKE) -C $(THREADUTIL_DIR) clean

install: upnp
	@if [ ! -d $(PREFIX)/usr/include/upnp ]; then \
		install -d $(PREFIX)/usr/include/upnp; \
	fi
	@if [ ! -d $(PREFIX)/usr/lib ]; then \
		install -d $(PREFIX)/usr/lib; \
	fi
	@if [ -f bin/$(DIR_PATH)upnp.jar ]; then \
		install bin/$(DIR_PATH)upnp.jar $(PREFIX)/usr/lib; \
	fi
	@install bin/$(DIR_PATH)libupnp.so $(PREFIX)/usr/lib/libupnp.so.$(VERSION)
	@ln -s $(PREFIX)/usr/lib/libupnp.so.$(VERSION) $(PREFIX)/usr/lib/libupnp.so
	@install inc/upnp.h $(PREFIX)/usr/include/upnp
	@install inc/config.h $(PREFIX)/usr/include/upnp
	@install inc/upnptools.h $(PREFIX)/usr/include/upnp

uninstall:
	@rm -f $(PREFIX)/usr/include/upnp/upnp.h
	@rm -f $(PREFIX)/usr/include/upnp/config.h
	@rm -f $(PREFIX)/usr/include/upnp/upnptools.h
	@rm -f $(PREFIX)/usr/lib/libupnp.so
	@rm -f $(PREFIX)/usr/lib/libupnp.so.$(VERSION)

test: upnp
	if [ ! -d bin/tests ]; then mkdir -p bin/tests ; fi
	if [ ! -d src/lib ]; then mkdir src/lib; fi
	cp bin/libupnp.so bin/tests/.
	cp ../ixml/bin/libixml.so bin/tests/.
	cp ../threadutil/bin/libthreadutil.so bin/tests/.
	$(MAKE) -C BuildTest
	cp BuildTest/Test bin/tests/.
	$(MAKE) -C upnptest
	cp upnptest/bin/Sdk* bin/tests/.
	cp upnptest/bin/*.* bin/tests/.

