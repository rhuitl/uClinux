
EXECS = cat chgrp chmod chown cmp cp dd grep l ln ls mkdir mkfifo mknod \
	more mv rm rmdir sync touch 
OBJS = cat.o chgrp.o chmod.o chown.o cmp.o cp.o dd.o grep.o l.o ln.o ls.o \
	mkdir.o mkfifo.o mknod.o more.o mv.o rm.o rmdir.o sync.o touch.o 

all: $(EXECS)

$(EXECS): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $@.o $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_CAT    /bin/cat
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_CHGRP  /bin/chgrp
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_CHMOD  /bin/chmod
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_CHOWN  /bin/chown
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_CMP    /bin/cmp
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_CP     /bin/cp
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_DD     /bin/dd
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_GREP   /bin/grep
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_L      /bin/l
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_LN     /bin/ln
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_LS     /bin/ls
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_MKDIR  /bin/mkdir
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_MKFIFO /bin/mkfifo
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_MKNOD  /bin/mknod
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_MORE   /bin/more
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_MV     /bin/mv
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_RM     /bin/rm
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_RMDIR  /bin/rmdir
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_SYNC   /bin/sync
	$(ROMFSINST) -e CONFIG_USER_FILEUTILS_TOUCH  /bin/touch

clean:
	rm -f $(EXECS) *.elf *.gdb *.o
