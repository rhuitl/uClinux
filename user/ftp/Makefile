
.EXPORT_ALL_VARIABLES:

DIRS = ftp

all:
	for i in $(DIRS) ; do make -C $$i $@ ; done

romfs:
	for i in $(DIRS) ; do make -C $$i $@ ; done

clean:
	-for i in $(DIRS) ; do make -C $$i clean ; done


