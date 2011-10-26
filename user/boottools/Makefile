EXECS = printbenv setbenv reset consume
SOURCES = xloader.c printbenv.c setbenv.c reset.c consume.c md5sum.c
CFLAGS += -I./include -I$(ROOTDIR)/$(LINUXDIR)/include

all: md5.o xloader md5sum $(EXECS)

ifeq ($(CONFIG_LIB_LIBBSC), y)
LIBBSC_DEP = libbsc.a
LIBBSC = -lbsc
LIBBSC_DIR = $(ROOTDIR)/user/boottools/
CFLAGS += -DCONFIG_LIB_LIBBSC -I$(LIBBSC_DIR)libs/bootstd/include
LDLIBS += -L$(LIBBSC_DIR)libs/bootstd/lib
libbsc.a: 
	[ -f $(LIBBSC_DIR)libs/bootstd/lib/$(LIBBSC_DEP) ] || (make -C $(LIBBSC_DIR)libs/bootstd)
else
LIBBSC_DEP =
endif

md5sum: md5sum.o md5.o
	$(CC) $(CFLAGS) $(CLFLAGS) $(LDFLAGS) md5.o -o $@ $< 

md5.o:	md5.c md5.h
	$(CC) $(LDFLAGS) -c md5.c

$(EXECS): $(SOURCES) $(LIBBSC_DEP)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $@.c $(LDLIBS) $(LIBBSC)

xloader: xloader.c md5.c md5.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $@.c md5.o $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER		/bin/xloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER	     -s /bin/xloader /bin/flashloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_LOADER         -s /bin/xloader /bin/ramloader
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_PRINTBENV		/bin/printbenv
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_SETBENV		/bin/setbenv
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_RESET		/bin/reset
	$(ROMFSINST) -e CONFIG_USER_BOOTTOOLS_MD5SUM		/bin/md5sum


# host development system tools for uCimage file manipulation:
uCbootstrap-tools:
	make -C uCbootstrap-tools

clean:
	rm -f $(EXECS) md5sum xloader *.elf *.gdb *.[oa] *~ core 
	[ -d $(LIBBSC_DIR)libs/bootstd ] && (make -C $(LIBBSC_DIR)libs/bootstd clean)
	make -C uCbootstrap-tools clean


.PHONY:	uCbootstrap-tools
