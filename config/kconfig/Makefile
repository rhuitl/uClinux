#
# Local Makefile for the configurator programs
#

CC = cc

# lxdialog pieces needed locally
check-lxdialog := lxdialog/check-lxdialog.sh
CFLAGS += $(shell $(CONFIG_SHELL) $(check-lxdialog) -ccflags)
LDLIBS += $(shell $(CONFIG_SHELL) $(check-lxdialog) -ldflags $(CC))

CPPFLAGS += $(shell $(CONFIG_SHELL) ./check.sh $(CC) $(CFLAGS) $(LDLIBS))

conf-objs := conf.o zconf.tab.o
mconf-objs := mconf.o zconf.tab.o
gconf-objs := gconf.o kconfig_load.o zconf.tab.o
qconf-objs := qconf.o kconfig_load.o zconf.tab.o
lxdialog-objs := lxdialog/checklist.o lxdialog/inputbox.o lxdialog/menubox.o \
	lxdialog/textbox.o lxdialog/util.o lxdialog/yesno.o

all: conf mconf

conf: $(conf-objs)

mconf: $(mconf-objs) $(lxdialog-objs)

gconf: $(gconf-objs)
gconf: CPPFLAGS += `pkg-config --cflags gtk+-2.0 gmodule-2.0 libglade-2.0` -D LKC_DIRECT_LINK
gconf: LDLIBS += `pkg-config --libs gtk+-2.0 gmodule-2.0 libglade-2.0`

%.moc: %.h
	`pkg-config --variable=prefix qt 2>/dev/null || pkg-config --variable=prefix qt-mt`/bin/moc -i $< -o $@
qconf.o: qconf.moc
qconf: $(qconf-objs)
qconf: CPPFLAGS += `pkg-config --cflags qt 2>/dev/null || pkg-config --cflags qt-mt` -D LKC_DIRECT_LINK
qconf: LDLIBS += `pkg-config --libs qt 2>/dev/null || pkg-config --libs qt-mt` -ldl

xconf: qconf

zconf.tab.o: zconf.tab.c zconf.hash.c lex.zconf.c

%.c: %.c_shipped
	cp $< $@

clean:
	rm -f conf mconf gconf qconf *.moc *.o .*.o.cmd lxdialog/*.o
