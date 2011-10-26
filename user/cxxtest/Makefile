SUBDIRS=sharedlib helloworld constructor exceptions iostream


all:
%:
	for i in $(SUBDIRS); do \
		make -C $$i $@ || exit 1; \
	done

#romfs:
#	for i in $(SUBDIRS); do \
#		make -C $$i $@ || exit 1; \
#	done

#clean:
#	for i in $(SUBDIRS); do \
#		make -C $$i $@; \
#	done
