/* scrts.c - auxiliary program to set the CRTSCTS flag on serial ttys
 *           called like: "scrts ttyS1 ttyS5"
 *           intended to be used on Linux, where sendfax cannot send the
 *           flag itself.
 */
#include <stdio.h>
#include <fcntl.h>
#include <termios.h>
#include <strings.h>

int main( int argc, char ** argv )
{
int i, fd;
struct termios tio;
char device[1000];

    for ( i=1; i<argc; i++ )
    {
	if ( strchr( argv[i], '/' ) == NULL )
	    sprintf( device, "/dev/%s", argv[i] );
	else
	    strcpy( device, argv[i] );

    	printf( "setting CRTSCTS for device %s...\n", device );

    	fd = open( device, O_RDONLY|O_NDELAY );
    	if ( fd == -1 )
    	{  perror( "open" ); break; }

    	if ( tcgetattr( fd, &tio ) == -1 )
    	{  perror( "tcgetattr" ); break; }

	if ( ( tio.c_cflag & CRTSCTS ) != 0 ) printf( "CRTSCTS was already set!\n" );

    	tio.c_cflag |= CRTSCTS;

    	if ( tcsetattr( fd, TCSANOW, &tio ) == -1 )
    	{  perror( "tcsetattr" ); break; }
    	close( fd );
    }
    return 0;
}
