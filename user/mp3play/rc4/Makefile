#
# Makefile for rc4 crypto code.
#

RC4LIB	= librc4.a
OBJS	= rc4_skey.o rc4_enc.o


all: $(RC4LIB)

$(RC4LIB): $(OBJS)
	$(AR) crv $(RC4LIB) $(OBJS)

clean:
	rm -f $(RC4LIB) $(OBJS) *.elf *.gdb

