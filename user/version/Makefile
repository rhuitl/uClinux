
include id.mk

EXEC = version
OBJS = version.o


all: $(EXEC) stamp.o

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

newversion:
	@if [ ! -f .version ]; then \
		echo 1 > .version; \
	else \
		expr 0`cat .version` + 1 > .version; \
	fi

compile.h: $(CONFIGURATION) version.h newversion
	@if [ -f .name ]; then \
	  echo \#define TOOLCHAIN_VERSION \"\#`cat .version`-`cat .name` `date`\"; \
	 else \
	  echo \#define TOOLCHAIN_VERSION \"\#`cat .version` `date`\";  \
	 fi >> .ver
	@echo \#define TOOLCHAIN_COMPILE_TIME \"`date +%T`\" >> .ver
	@echo \#define TOOLCHAIN_COMPILE_BY \"`whoami`\" >> .ver
	@echo \#define TOOLCHAIN_COMPILE_HOST \"`hostname`\" >> .ver
	@if [ -x /bin/dnsdomainname ]; then \
	  echo \#define TOOLCHAIN_COMPILE_DOMAIN \"`dnsdomainname`\"; \
	elif [ -x /bin/domainname ]; then \
	  echo \#define TOOLCHAIN_COMPILE_DOMAIN \"`domainname`\"; \
	else \
	  echo \#define TOOLCHAIN_COMPILE_DOMAIN ; \
	fi >> .ver
	@echo \#define TOOLCHAIN_COMPILER \"`$(CC) -v 2>&1 | tail -1`\" >> .ver
	@mv -f .ver $@

version.h: ./Makefile id.mk
	@echo \#define TOOLCHAIN_BANNER \"$(BANNER)\" > .ver
	@echo \#define TOOLCHAIN_NAME \"$(TOOLCHAIN)\" >> .ver
	@echo \#define TOOLCHAIN_RELEASE \"$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)\" >> .ver
	@echo \#define TOOLCHAIN_VERSION_CODE `expr $(VERSION) \\* 65536 + $(PATCHLEVEL) \\* 256 + $(SUBLEVEL)` >> .ver
	@mv -f .ver $@

version.o: version.c compile.h

stamp.o: stamp.c compile.h version.h

