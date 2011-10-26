EXEC = jpegview 

LDLIBS  += -ljpeg

all: $(EXEC)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

.PHONY: all clean romfs
