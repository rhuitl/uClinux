
/*  argvmks.c

    for MKS Korn Shell

    If you use this file, add -DHAVE_REARGV=1 to your
    CFLAGS

    Contributed by Jack Fitts (fittsj%wmv009@bcsaic.boeing.com)

*/

/*
$Log: argvmks.c,v $
 * Revision 1.2  1995/01/07  14:47:24  mike
 * remove return 1 from void function
 *
 * Revision 1.1.1.1  1993/07/03  18:58:49  mike
 * move source to cvs
 *
 * Revision 1.2  1992/12/17  02:48:01  mike
 * 1.1.2d changes for DOS
 *
 * Revision 1.1  1992/12/05  22:38:41  mike
 * Initial revision
 *
*/


/***********************************************************/
/*                                                         */
/* prototypes for reargv                                   */
/*                                                         */
/***********************************************************/

void *malloc(unsigned) ;
char * basename ( char * );
char *strcpy(char* , char*) ;


/***********************************************************/
/*                                                         */
/* reargv reset argc/argv from environment for MKS shell   */
/*                                                         */
/***********************************************************/


void reargv ( int *argcp, char *** argvp ) {

    int i = 0;
    int cnt ;
    char ** v;
    extern char **environ ;
    register char **pe = environ;

/* MKS Command line args are in the first n lines of the environment */
/* each arg is preceded with a tilde (~)*/

    while ( **(pe++) == '~' )
        i++;

/* if no tilde found then not running under MKS */

    if ( ! i )  return ;

/* malloc space for array of char pointers */

    if ( ! ( v = ( char ** ) malloc (( i + 1 ) * sizeof ( char* ))) )
        return ;

/* set argc to number of args in environ */

    *argcp = cnt = i;

/* set char pointers to each command line arg */
/* jump over the tilde which is the first char in each string */

    for ( i = 0; i < cnt ; i++ )
        v[i] = environ[i]+1;

    /*set last arg to null*/

    v[cnt] = (char *) 0 ;
    
    /*strip leading directory stuff from argv[0] */

    v[0] = basename(v[0]);

    *argvp = v;
}


/***********************************************************/
/*                                                         */
/* basename                                                */
/*                                                         */
/***********************************************************/

static char * basename ( char * s ) {

    register char * p ;
    char *last ;
    
    /* find the last occurrence of ':' '\\' or '/' */
    p = s ;  last = (char *) 0 ;
    while ( *p ) {
	if ( *p == ':' || *p == '\\' || *p == '/' ) last = p ;
	p++ ;
    }

    return last ? last+1 : s ;
}
