DIRS = src src/server

all:
	for i in $(DIRS) ; do make -C $$i || exit $? ; done

romfs:
	for i in $(DIRS) ; do make -C $$i romfs || exit $? ; done

clean:
	-for i in $(DIRS) ; do make -C $$i clean ; done
