
EXEC = unzoo
OBJS = unzoo.o

CFLAGS += -DSYS_IS_UNIX -DSYS_HAS_MKDIR

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

