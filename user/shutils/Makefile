
EXECS = basename date dirname echo false logname printenv pwd true \
	uname which whoami yes
OBJS = basename.o date.o dirname.o echo.o false.o logname.o printenv.o \
	pwd.o true.o uname.o which.o whoami.o yes.o

all: $(EXECS)

$(EXECS): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $@.o $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_BASENAME /bin/basename
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_DATE     /bin/date
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_DIRNAME  /bin/dirname
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_ECHO     /bin/echo
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_FALSE    /bin/false
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_LOGNAME  /bin/logname
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_PRINTENV /bin/printenv
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_PWD      /bin/pwd
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_TRUE     /bin/true
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_UNAME    /bin/uname
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_WHICH    /bin/which
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_WHOAMI   /bin/whoami
	$(ROMFSINST) -e CONFIG_USER_SHUTILS_YES      /bin/yes

clean:
	rm -f $(EXECS) *.gdb *.elf *.o
