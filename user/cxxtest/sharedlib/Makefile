all: libs cxx_test

libs:
	make -C lib

cxx_test:
	make -C app

clean:
	-make -C app clean
	-make -C lib clean

romfs:
	$(ROMFSINST) lib/libstdm++.so /lib/libstdm++.so
	$(ROMFSINST)  app/cxx_shared /bin/cxx_shared
