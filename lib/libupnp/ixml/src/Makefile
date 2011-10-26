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

ifeq ($(JNI),1)
  TARGET_OUTPUT = libixmlJNI.so
else
  TARGET_OUTPUT = libixml.so
endif

ifdef NOT_DEFINED
ifdef TARGET
  CC    = $(TARGET)-gcc
  AR    = $(TARGET)-ar
  LD    = $(TARGET)-ld
  STRIP = $(TARGET)-strip
else
  CC    = gcc
  AR    = ar
  LD    = ld
  STRIP = strip
endif
endif

ifeq ($(INSURE), 1)
  CC = insure
endif

ifeq ($(DEBUG), 1)
  OBJ_DIR     = obj/debug
  EXT_LIB_DIR = debug
else
  OBJ_DIR     = obj
  EXT_LIB_DIR =
endif

ifdef TARGET
  OBJ_DIR     := $(OBJ_DIR)/$(TARGET)
  EXT_LIB_DIR := $(EXT_LIB_DIR)/$(TARGET)
endif

LFLAGS=-L ../../pil/lib/$(EXT_LIB_DIR)
CFLAGS+=-Wall -I./ -I../inc -I../../pil/inc
DYN_CFLAGS=-fPIC

ifeq ($(DEBUG),1)
  DEBUG_FLAGS = -O -g -DDEBUG
else
  DEBUG_FLAGS = -Os -DNDEBUG
  STRIPU      = $(STRIP) $(OBJ_DIR)/$(TARGET_OUTPUT)
endif

ifeq ($(DEBUG),1)
  IXML_DIR = ../bin/debug/$(TARGET)
else
  IXML_DIR = ../bin/$(TARGET)
endif

ifeq ($(JNI),1)
  OBJ = $(OBJ_DIR)/ixmlJNI.o
  LIBS = $(IXML_DIR)libixml.so
else 
  OBJ = $(OBJ_DIR)/ixml.o       $(OBJ_DIR)/node.o $(OBJ_DIR)/ixmlparser.o \
        $(OBJ_DIR)/ixmlmembuf.o $(OBJ_DIR)/nodeList.o \
        $(OBJ_DIR)/element.o    $(OBJ_DIR)/attr.o $(OBJ_DIR)/document.o \
        $(OBJ_DIR)/namedNodeMap.o
  LIBS = 
endif

VERSION=1.2.1

CFLAGS += -fPIC -c -Wall
C2FLAGS = -Wall $(DEFS) -shared -Wl,-soname,$(TARGET_OUTPUT)
INCLUDES = -I. -I../inc -Iinc

ifeq ($(EFENCE),1)
  C2FLAGS +=  -lefence
endif


$(OBJ_DIR)/%.o:	%.c
	@-mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(INCLUDES) -c $< -o $@

$(OBJ_DIR)/$(TARGET_OUTPUT): $(OBJ)
#	$(CC) $(C2FLAGS) $(OBJ) $(LIBS) -o $(OBJ_DIR)/$(TARGET_OUTPUT)
	$(CC) $(C2FLAGS) $(SH_LDFLAGS) $(OBJ) $(LIBS) -o $(OBJ_DIR)/$(TARGET_OUTPUT) $(SH_LDLIBS)
	$(STRIPU)
	@-mkdir -p $(IXML_DIR)
	@cp $(OBJ_DIR)/$(TARGET_OUTPUT) $(IXML_DIR)

MORE_FLAGS = -I$(JAVA_DIR)/include -I$(JAVA_DIR)/include/linux

$(OBJ_DIR)/ixmlJNI.o: jni/ixmlJNI.c  $(IXML_DIR)/ixml.jar
	@-mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(MORE_FLAGS) $(DEBUG_FLAGS) $(INCLUDES) -c jni/ixmlJNI.c -o $@


$(IXML_DIR)/ixml.jar: 
	$(JAVA_DIR)/bin/javac  jni/com/intel/ixml/*.java
	cd jni; $(JAVA_DIR)/bin/jar cf ../$@ com/intel/ixml/*.class
clean:
	@rm -rf $(OBJ_DIR)
	@rm $(IXML) -f

install: $(OBJ_DIR)/$(TARGET_OUTPUT)
	@if [ ! -d $(PREFIX)/usr/include/upnp ]; then \
		install -d $(PREFIX)/usr/include/upnp; \
	fi
	@if [ ! -d $(PREFIX)/usr/lib ]; then \
		install -d $(PREFIX)/usr/lib; \
	fi
	@install $(IXML_DIR)/$(TARGET_OUTPUT) $(PREFIX)/usr/lib

uninstall:
	@rm -f $(PREFIX)/usr/include/upnp/ixml.h
	@rm -f $(PREFIX)/usr/include/upnp/ixmlold.h
	@rm -f $(PREFIX)/usr/lib/$(TARGET_OUTPUT)

