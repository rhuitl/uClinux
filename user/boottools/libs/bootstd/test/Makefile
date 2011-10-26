PRGS = bsc_setenv bsc_getenv bsc_gethwaddr bsc_getserialnum bsc_version bsc_readenv \
       bsc_reset bsc_eraseall bsc_free_gc bsc_setpmask \
       test_free test_version test_gc test_getenv test_readenv test_gethwaddr

all: $(PRGS)

$(PRGS): 
	$(CC) $(CFLAGS) $(CLFLAGS) $(LDFLAGS)  -o $@ $@.c $(LDLIBS) -lbsc

install:

clean:
	rm -f *.[oa] *.gdb *.elf *~ core $(PRGS)
