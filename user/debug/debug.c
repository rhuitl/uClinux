#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/traps.h>

void usage( void )
{
	fprintf( stderr, "Usage: debug <application> <args..>\n" );
}


    
int main( int argc, char *argv[] )
{
	int i;
	if ( argc < 2 || !strcmp( argv[1], "--help" ) ) {
		usage();
		return 1;
	}

//	printf("DEBUG: trapping to kernel to flag current process for debugging ...\n");
    __asm__ __volatile__ ("movi r2, %0\n\t"
					 "trap"
					 :
					 :"i" (TRAP_ID_APPDEBUG) 
					 :"r2");

	printf( "DEBUG: running \"%s", argv[1] );
	for(i = 2; i < argc; i++) printf( " %s", argv[i] );
	printf( "\" ...\n" );

	execvp( argv[1], &(argv[1]) );
	printf("%s: %s\n", argv[1], (errno == ENOENT) ? "Bad command or file name" : strerror(errno));
	_exit(0);
}

