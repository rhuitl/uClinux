default: lwepgen

lwepgen: lwepgen.c
	 gcc -Wl,/usr/lib/libcrypto.so -o lwepgen lwepgen.c
	 
lwepgen.c:
	echo lwepgen.c missing!
	false

clean:
	rm -rf lwepgen
