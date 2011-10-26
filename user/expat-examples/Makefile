VPATH=../../lib/expat/examples

EXE1=expat_outline
EXE2=expat_elements

EXTRA_LIBS = $(SLIBEXPAT)

EXE1OBJS=outline.o
EXE2OBJS=elements.o

all: $(EXE1) $(EXE2)

$(EXE1): $(EXE1OBJS)
	$(CC) $(LDFLAGS) -o $@ $(EXE1OBJS) $(EXTRA_LIBS) $(LDLIBS)

$(EXE2): $(EXE2OBJS)
	$(CC) $(LDFLAGS) -o $@ $(EXE2OBJS) $(EXTRA_LIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXE1)
	$(ROMFSINST) /bin/$(EXE2)

clean:
	-rm -f $(EXE1) $(EXE2) *.elf *.gdb *.o
