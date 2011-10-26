
EXEC = cgi_demo
OBJS = cgi.o cgivars.o htmllib.o template.o

all: $(EXEC)

romfs:
	$(ROMFSINST) $(ROOTDIR)/vendors/Generic/httpd /home/httpd
	$(ROMFSINST) /home/httpd/cgi-bin/cgi_demo

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
	

$(OBJS): cgivars.h htmllib.h template.h
