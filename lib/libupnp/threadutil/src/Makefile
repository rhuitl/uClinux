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

DEPDIR = .deps
df = $(DEPDIR)/$(*F)

ifeq ($(EMACS),1)
NOCOLOR  = export TERM=dumb;
else
NOCOLOR =
endif

ifeq ($(STATS),1)
DEBUG_FLAGS += -DSTATS
endif

ifeq ($(INSURE),1)
CC = insure -pthread
else
ifeq ($(DEBUG),1)
STRIPU =
else
STRIPU = $(STRIP) $(TARGET_OUTPUT)
endif
endif

ifeq ($(DEBUG),1)
DEBUG_FLAGS = -g -O -DDEBUG -DSTATS
LOCALDIR =../bin/debug/$(DIR_PATH)
TARGET_OUTPUT = libthreadutil_dbg.so
OBJ_DIR = obj/debug/$(DIR_PATH)
CLEAN_PATH=debug/$(DIR_PATH)
else
DEBUG_FLAGS += -Os -DNO_DEBUG -DNDEBUG
LOCALDIR +=../bin/$(DIR_PATH)
TARGET_OUTPUT = libthreadutil.so
OBJ_DIR = obj/$(DIR_PATH)
CLEAN_PATH=$(DIR_PATH)
endif

CXX =$(CROSS_COMPILER)g++
CFLAGS += -fPIC -Wall -D_REENTRANT -I../inc
INCLUDE =
SHAREDFLAGS = -rdynamic -shared -Wl,-soname,

libthreadutil.so_objects = $(OBJ_DIR)FreeList.o    \
                           $(OBJ_DIR)LinkedList.o  \
                           $(OBJ_DIR)ThreadPool.o  \
                           $(OBJ_DIR)TimerThread.o \
			   $(OBJ_DIR)iasnprintf.o

#libthreadutil.so_libs = -lpthread 
libthreadutil.so_libs = $(LIBPTHREAD)

ifeq ($(EFENCE),1)
libthreadutil.so_libs += -lefence
endif

libthreadutil_dbg.so_objects = $(libthreadutil.so_objects)
libthreadutil_dbg.so_libs = $(libthreadutil.so_libs)


$(OBJ_DIR)%.o : 	%.c
	@-mkdir -p $(OBJ_DIR)
	$(NOCOLOR) $(CC) $(CFLAGS) -MMD $(INCLUDE) $(DEBUG_FLAGS) -c $< -o $@


libthread%.so:
#	$(NOCOLOR) $(CC) $(CFLAGS) $(INCLUDE) $(DEBUG_FLAGS) $(SHAREDFLAGS)$@ $^ $($@_libs) -o $@
	$(NOCOLOR) $(CC) $(CFLAGS) $(SH_LDFLAGS) $(INCLUDE) $(DEBUG_FLAGS) $(SHAREDFLAGS)$@ $^ $($@_libs) -o $@ $(SH_LDLIBS)
	$(STRIPU)
	@-mkdir -p $(LOCALDIR)
	@cp $@ $(LOCALDIR)

all: depdir $(TARGET_OUTPUT)

install: $(TARGET_OUTPUT)
	@if [ ! -d $(PREFIX)/usr/include/upnp ]; then \
		@install -d $(PREFIX)/usr/include/upnp; \
	fi
	@install ../inc/LinkedList.h  $(PREFIX)/usr/include/upnp
	@install ../inc/FreeList.h    $(PREFIX)/usr/include/upnp
	@install ../inc/ThreadPool.h  $(PREFIX)/usr/include/upnp
	@install ../inc/TimerThread.h $(PREFIX)/usr/include/upnp
	@install ../inc/iasnprintf.h  $(PREFIX)/usr/include/upnp
	@install ../inc/ithread.h     $(PREFIX)/usr/include/upnp
	@if [ ! -d $(PREFIX)/usr/lib ]; then \
		@install -d $(PREFIX)/usr/lib; \
	fi
	@install $(TARGET_OUTPUT) $(PREFIX)/usr/lib

uninstall:
	@rm -f $(PREFIX)/usr/include/upnp/LinkedList.h
	@rm -f $(PREFIX)/usr/include/upnp/FreeList.h
	@rm -f $(PREFIX)/usr/include/upnp/ThreadPool.h
	@rm -f $(PREFIX)/usr/include/upnp/TimerThread.h
	@rm -f $(PREFIX)/usr/include/upnp/iasnprintf.h
	@rm -f $(PREFIX)/usr/include/upnp/ithread.h
	@rm -f $(PREFIX)/usr/include/upnp/withread.h
	@rm -f $(PREFIX)/usr/lib/$(TARGET_OUTPUT)

depdir:
	@-mkdir -p .deps


libthreadutil_dbg.so: $(libthreadutil_dbg.so_objects)

libthreadutil.so: $(libthreadutil.so_objects)

-include $(libthreadutil.so_objects:%.o=$(DEPDIR)/%.P)


clean1:
	@rm -rf $(OBJ_DIR)
	@rm -f ../bin/$(CLEAN_PATH)/$(TARGET_OUTPUT)
clean:
	@rm -rf $(OBJ_DIR)
	@rm -rf ../bin

