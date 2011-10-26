
.EXPORT_ALL_VARIABLES:

DIRS = Tremor
EXEC = oggplay
OBJS = oggplay.o Tremor/libvorbisidec.a

EXEC2 = oggenc
OBJS2 = oggenc.o

.PHONY: clean romfs all $(DIRS)

CFLAGS += -Wall
CPPFLAGS += -I$(DIRS)

all: $(DIRS) $(EXEC) $(EXEC2)

$(EXEC): $(OBJS)
$(EXEC2): $(OBJS2)

Tremor/libvorbisidec.a:
	$(MAKE) -C Tremor

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) /bin/$(EXEC2)
#	for i in $(DIRS) ; do make -C $$i $@ || exit $?; done

clean:
	-rm -f $(EXEC) $(EXEC2) *.elf *.gdb *.o
	for i in $(DIRS) ; do make -C $$i clean ; done
