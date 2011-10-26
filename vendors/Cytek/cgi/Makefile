
EXEC = cgi_demo

OBJS = cgi.o cgivars.o htmllib.o template.o
	

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
	

$(OBJS): cgivars.h htmllib.h template.h
