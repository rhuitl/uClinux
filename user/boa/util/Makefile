all:	cpsel	cp-test boa_indexer

clean:	
	rm cpsel cp-test 

cpsel:	cpsel.c	cpsel.config.h
	gcc -o cpsel cpsel.c

cp-test: cp-test.c
	gcc -o cp-test cp-test.c
	
boa_indexer: index_dir.c
	gcc -o boa_indexer index_dir.c
