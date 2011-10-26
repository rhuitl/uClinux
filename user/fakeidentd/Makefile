EXEC = identd

all: $(EXEC)

$(EXEC):
	CC=$(CC) sh identd.c $(CFLAGS) $(LDFLAGS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC)
