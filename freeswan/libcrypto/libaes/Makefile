CFLAGS=-O3 -fomit-frame-pointer -Wall $(EXTRA_CFLAGS)
INC=-I../include 

AES_CORE_OBJ:=aes.o

ASM-$(ARCH_ASM):=1
ASM_X86:=$(ASM-i586)$(ASM-i686)
ifneq ($(strip $(ASM_X86)),)
AES_CORE_OBJ:= asm/aes-i586.o
endif

ifdef CONFIG_HW_ASSIST
EXTRA_CFLAGS += -DHW_ASSIST=1
AES_CORE_OBJ += 
endif

LIBOBJ := aes_xcbc_mac.o aes_cbc.o $(AES_CORE_OBJ)
LDLIBS := -laes
LDFLAGS := -L.

BLIB := libaes.a

L_TARGET := $(BLIB)

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(INC) -c $< -o $@

.S.o:
	$(CC) $(AFLAGS) -c $< -o $@

$(BLIB): $(LIBOBJ)
	/bin/rm -f $(BLIB)
	$(AR) crs $(BLIB) $(LIBOBJ)

testx: test_main_mac.o $(BLIB)
	$(CC) -o $@ $^ 

test: test_main.o $(BLIB)
	$(CC) -o $@ $^ 

clean:
	rm -f *.[oa] asm/*.o core $(TARGET) test testx
