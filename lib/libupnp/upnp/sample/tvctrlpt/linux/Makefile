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

INCLUDES= -I../../../inc  -I../../common -I ../

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
OPT = -g -O2
DEBUG_OPTION = DEBUG=1
LIBS= ../../../bin/debug/$(DIR_PATH)libupnp.so ../../../bin/debug/$(DIR_PATH)libthreadutil_dbg.so \
      ../../../bin/$(DIR_PATH)libixml.so
else
DEBUG_OPTION =
OPT = -O2
LIBS= ../../../bin/$(DIR_PATH)libupnp.so ../../../bin/$(DIR_PATH)libthreadutil.so \
      ../../../bin/$(DIR_PATH)libixml.so
endif

CFLAGS += -Wall $(OPT)

APPS = upnp_tv_ctrlpt

all: $(APPS)


upnp_tv_ctrlpt: ../upnp_tv_ctrlpt.o ../../common/sample_util.o upnp_tv_ctrlpt_main.o $(LIBS)
	$(CC)  $(CFLAGS) upnp_tv_ctrlpt.o sample_util.o  upnp_tv_ctrlpt_main.o $(LIBS) -o  $@ 
	@echo "make $@ finished on `date`"

../../../bin/libupnp.so:
	cd ../../../; make 

../../../bin/debug/libupnp.so:
	cd ../../../; make DEBUG=1

%.o:	%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean:
	rm -f *.o $(APPS)


