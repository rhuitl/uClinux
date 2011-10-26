-include ../user.mak

# Set to enable memory debugging commands
# CFLAGS += -DTCL_MEM_DEBUG

# A lot of work is done on the stack. If this is too small, we will just
# crash and burn
FLTFLAGS += -s 40000

EXE=tclsh
STATIC_LIBTCL=libtcl.a
CFLAGS += -Wall -g -I.
ifdef CONFIG_LIB_TINYTCL_STATIC
LIBTCL=$(STATIC_LIBTCL)
else
LIBTCL=libtcl.so
CFLAGS += -fPIC
endif
.EXPORT_ALL_VARIABLES:

OBJS=tclAssem.o tclGet.o tclBasic.o tclGlob.o tclUtil.o panic.o tclCmdAH.o tclHash.o tclCmdIL.o tclParse.o \
	regex_compat.o tclCmdMZ.o tclEnv.o tclProc.o tclVar.o tclalloc.o tclExpr.o tclunxaz.o tcluxutl.o tcluxstr.o \
	tclXdbg.o tclXgen.o tclHistory.o tclmod.o

# Defines the extensions to include from extension/...
EXTENSIONS=syslog cgi
ifdef CONFIG_LEDMAN
EXTENSIONS += ledman
endif

# For dynamic loading
ifndef CONFIG_LIB_TINYTCL_STATIC
CFLAGS += -DHAVE_TCL_LOAD
LDFLAGS += -rdynamic
EXTRALIBS += -ldl
OBJS += tclLoad.o tclLoadDl.o noextensions.o
else
OBJS += load_extensions.o
endif

ifdef CONFIG_USER_TINYTCL_DEBUGGER
# If you want to add the debugger...
OBJS += debugger/Dbg.o debugger/Dbg_cmd.o
CFLAGS += -Idebugger -DDEBUGGER -DDEBUGGER_INIT=\"Dbg_lib.tcl\"
endif

TARGETS += $(LIBTCL)
ifdef UCLINUX_BUILD_USER
TARGETS += $(EXE)
endif

all: $(TARGETS) build_extensions

$(EXE): $(LIBTCL) tinytcl.o
	$(PURIFY) $(CC) $(LDFLAGS) -o $@ tinytcl.o $(LIBTCL) $(LDLIBS$(LDLIBS_$@)) $(EXTRALIBS)

tcltest: $(LIBTCL) tclTest.o
	$(PURIFY) $(CC) $(LDFLAGS) -o $@ tclTest.o $(LIBTCL) $(LDLIBS$(LDLIBS_$@)) $(EXTRALIBS)

$(STATIC_LIBTCL): $(OBJS) build_extensions
	$(AR) cr $@ $(OBJS)
	-$(AR) r $@ extensions/*.o

libtcl.so: $(OBJS)
	$(CC) -shared -o $@ $(SH_LDFLAGS) $(OBJS) $(SH_LDLIBS)

# The dependency here is a bit overkill, but it's simple
build_extensions: $(LIBTCL) extensions/*/*
	@for e in $(EXTENSIONS); do \
		$(MAKE) -C extensions/$$e TCLDIR=../.. || exit 1; \
	done
	touch build_extensions

load_extensions.c:
	@echo "#include \"tcl.h\"" > $@
	@for i in $(EXTENSIONS); do \
		echo "extern void $${i}_Init(Tcl_Interp *interp);" >>$@; \
	done
	@echo "void init_extensions(Tcl_Interp *interp) {" >> $@
	@for i in $(EXTENSIONS); do \
		echo "$${i}_Init(interp);" >>$@; \
	done
	@echo "}" >>$@

clean:
	rm -f *.o lib*.a lib*.so $(EXE) load_extensions.c tcltest extensions/*.o build_extensions
	for e in $(EXTENSIONS); do \
		$(MAKE) -C extensions/$$e $@; \
	done

romfs:
	$(ROMFSINST) -d -e CONFIG_USER_TINYTCL_TCLSH /bin/tclsh
ifndef CONFIG_LIB_TINYTCL_STATIC
	$(ROMFSINST) /lib/libtcl.so
	for e in $(EXTENSIONS); do \
		$(MAKE) -C extensions/$$e $@; \
	done
endif
# DO NOT DELETE

dos.o: tcl.h tclExtdInt.h tclExtend.h tclInt.h tclHash.h
noextensions.o: tcl.h
readdir.o: tclExtdInt.h tclExtend.h tcl.h tclInt.h tclHash.h tclUnix.h
tclalloc.o: tclInt.h tclHash.h
tclAssem.o: tclInt.h tclHash.h
tclBasic.o: tclInt.h tclHash.h
tclCmdAH.o: tclInt.h tclHash.h
tclCmdIL.o: tclInt.h tclHash.h tclUnix.h
tclCmdMZ.o: tclInt.h tclHash.h
tclEmbed.o: tcl.h
tclEnv.o: tclInt.h tclHash.h tclUnix.h
tclExpr.o: tclInt.h tclHash.h
tclGet.o: tclInt.h tclHash.h
tclGlob.o: tclInt.h tclHash.h tclUnix.h
tclHash.o: tclInt.h tclHash.h
tclHistory.o: tclInt.h tclHash.h
tclLoad.o: tclExtdInt.h tclExtend.h tcl.h tclInt.h tclHash.h tclLoad.h
tclLoadDl.o: tclInt.h tclHash.h tclLoad.h
tclParse.o: tclInt.h tclHash.h
tclProc.o: tclInt.h tclHash.h
tclTest.o: tcl.h
tclunxaz.o: tclInt.h tclHash.h tclUnix.h
tclUtil.o: tclInt.h tclHash.h
tcluxstr.o: tclInt.h tclHash.h tclUnix.h
tcluxutl.o: tclInt.h tclHash.h tclUnix.h
tclVar.o: tclInt.h tclHash.h
tclXdbg.o: tclExtdInt.h tclExtend.h tcl.h tclInt.h tclHash.h
tclXgen.o: tclExtdInt.h tclExtend.h tcl.h tclInt.h tclHash.h
tinytcl.o: tcl.h tclExtdInt.h tclExtend.h tclInt.h tclHash.h
