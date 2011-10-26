#
#	lsof has a crazy script based "Configure" setup. So I have
#	manually run it, and fixed up the cross compile issues in the
#	Makefiles. We also manually make and clean the linux file
#	links here.
#
FILES = dlsof.h dproto.h dfile.c dmnt.c dnode.c dproc.c dsock.c dstore.c
LINKFILES = $(addprefix lsof/,$(FILES))


all: $(LINKFILES)
	$(MAKE) -C lsof

$(LINKFILES):
	ln -s dialects/linux/$(notdir $@) $@

clean:
	$(MAKE) -C lsof clean
	rm -f $(LINKFILES)

romfs:
	$(ROMFSINST) lsof/lsof /bin/lsof

