#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/times.h>

#ifdef ISC
#include <sys/bsdtypes.h>
#endif

#include "mgetty.h"
#include "policy.h"

void exit_usage _P1( (retcode), int retcode )
{
    fprintf( stderr, "usage: faxin [-d <spool_directory>] [-x <debug>]\n");
    exit( retcode );
}

char * Device;		/* faxrec() needs it [for the filenames] */
time_t call_start;	/* ditto */

char * CallerId = "unknown";	/* only available in mgetty / cnd.c */
char * CallName = "unknown";	/* ditto */

int main _P2( (argc, argv), int argc, char ** argv )
{
char * fax_spool_in = FAX_SPOOL_IN;
int  c;
char log_path[MAXPATH];

    while ((c = getopt(argc, argv, "x:d:")) != EOF) {
	switch (c) {
	case 'x':
		log_set_llevel( atoi(optarg) );
		break;
	case 'd':
		fax_spool_in = optarg;
		break;
	case '?':
		exit_usage(2);
		break;
	}
    }

    /* get the name of the tty stdin is connected to (jcp) */
    Device = ttyname(STDIN_FILENO);

    if ( Device == NULL || *Device == '\0' ) Device = "unknown";

    /* if present, remove the leading "/dev/" prefix */
    if ( strncmp( Device, "/dev/", 5 ) == 0 ) Device += 5;

    /* remember the start time */
    call_start = time( NULL );

    /* construct the log path string */
    sprintf( log_path, LOG_PATH, Device );

    /* initialize logging subsystem */
    log_init_paths( argv[0], log_path, &Device[strlen(Device)-2] );


    /* receive the fax */
    faxrec( fax_spool_in, 0, -1, -1, 644, NULL );
    return 0;
}

