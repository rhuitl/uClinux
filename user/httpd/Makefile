
EXEC = httpd
OBJS = httpd.o copy.o

HTTPD_DOCUMENT_ROOT = /home/httpd
CFLAGS += -DHTTPD_DOCUMENT_ROOT=\"$(HTTPD_DOCUMENT_ROOT)\"

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

