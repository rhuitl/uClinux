
EXEC = setserial
OBJS = setserial.o
#CFLAGS += -DHAVE_ASM_IOCTLS_H -DHAVE_LINUX_HAYESESP_H
CFLAGS += -DHAVE_ASM_IOCTLS_H

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

