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

ifeq ($(INSURE),1)
CC = insure
endif

LIBS = ../lib

UPNP_INC_DIR = -I../inc -I../../inc -I ../../../threadutil/src/win32 \
	-I ../../../threadutil/src -I ../../../ixml/inc


CFLAGS += -fPIC -Wall -c -D_REENTRANT $(UPNP_INC_DIR) 

ifeq ($(DEBUG),1)
CFLAGS += -g -O -DDEBUG
OBJ_DIR = obj/debug/$(DIR_PATH)
UPNP_LIB_DIR = $(LIBS)/debug/$(DIR_PATH)
else
CFLAGS += -Os  -DNO_DEBUG -DNDEBUG
OBJ_DIR = obj/$(DIR_PATH)
UPNP_LIB_DIR = $(LIBS)/$(DIR_PATH)
endif


ifeq ($(CLIENT),1)
CFLAGS += -DINCLUDE_CLIENT_APIS
endif

ifeq ($(DEVICE),1)
CFLAGS += -DINCLUDE_DEVICE_APIS
endif

TARGET_OUTPUT=$(UPNP_LIB_DIR)ssdp.o 

OBJECTS = $(OBJ_DIR)ssdp_device.o $(OBJ_DIR)ssdp_ctrlpt.o $(OBJ_DIR)ssdp_server.o

all: $(TARGET_OUTPUT) $(OBJECTS)

$(TARGET_OUTPUT): $(OBJECTS) 
	$(LD) -r  $(OBJECTS) -o $(TARGET_OUTPUT)

$(OBJ_DIR)%.o: %.c
	@-mkdir -p $(OBJ_DIR)
	@-mkdir -p $(UPNP_LIB_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@if [ -d "$(LIBS)" ]; then rm -rf $(LIBS); fi    
	@rm -f $(UPNP_LIB_DIR)/*.o
	@rm -rf $(OBJ_DIR)
	@rm -f *.o


