
EXEC = ivorbisfile_example
OBJS = ivorbisfile_example.o

LIBOV = libvorbisidec.a
LIBOBJS = bitwise.o block.o codebook.o floor0.o floor1.o framing.o \
	  info.o mapping0.o mdct.o registry.o res012.o sharedbook.o \
	  synthesis.o vorbisfile.o window.o

CFLAGS += -DPACKAGE=\"libvorbisidec\" -DVERSION=\"1.0.2\" \
	  -DHAVE_DLFCN_H=1 -DHAVE_ALLOCA_H=1 -DHAVE_ALLOCA=1 \
	  -D_REENTRANT -DUSE_MEMORY_H \
	  -fsigned-char -I.

FLTFLAGS += -s 16384


all: $(EXEC)

$(EXEC): $(LIBOV) $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBOV) $(LDLIBS)

$(LIBOV): $(LIBOBJS)
	$(AR) cvr $(LIBOV) $(LIBOBJS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) $(EXEC) /bin/example

clean:
	-rm -f $(EXEC) $(LIBOV) *.elf *.gdb *.o *.lo

