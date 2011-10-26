#ident "$Id: faxq-helper.c,v 4.16 2005/04/10 20:47:43 gert Exp $ Copyright (c) Gert Doering"

/* faxq-helper.c
 *
 * this is a suid helper process that is used for the unprivileged
 * fax queue client programs (faxspool, faxq, faxrm) to access the
 * /var/spool/fax/outgoing/... fax queue ($OUT).
 *
 * it is NOT suid "root" but suid "FAX_OUT_USER" (usually "fax") as
 * defined in the top level mgetty Makefile
 *
 * there are 5 commands:
 *
 * faxq-helper new
 *       user permission check (fax.allow + fax.deny)
 *       return a new job ID (F000123) and create "$OUT/.inF000123.$uid/"
 *
 * faxq-helper input $ID $filename
 *       validate $filename
 *       open $OUT/.in$ID.uid/$filename (O_EXCL)
 *       copy stdin to file
 *
 * faxq-helper activate $ID
 *       take prototype JOB file from stdin, 
 *	     check that "pages ..." does not reference any non-local 
 *	     or non-existing files
 *	     check that "user ..." contains the correct value
 *	 create JOB
 *       move $OUT/.inF000134.$uid/ to $OUT/F000134/ -> faxrunq will "see" it
 *
 * faxq-helper remove $ID
 *       check that $OUT/$ID/ exists and belongs to the calling user
 *       lock JOB
 *       rm -r $OUT/$ID/ directory tree
 *
 * faxq-helper requeue $ID
 *       check that $OUT/$ID/ exists and belongs to the calling user
 *       move $JOB.error to $JOB to reactivate job
 *       touch $queue_changed
 *
 * some checks are done globally for all commands
 *       faxq-helper must be suid fax, and fax user must exist in passwd
 *       $FAX_SPOOL_OUT must exist
 *       if $OUT is world- or group-writeable, or not owned by 'fax', issue 
 *        warning (but go on) - this could be legal, but it's off-spec
 *
 * Note: right now, this needs an ANSI C compiler, and might not be 
 *       as portable as the remaining mgetty code.  Send diffs :-)
 *
 * $Log: faxq-helper.c,v $
 * Revision 4.16  2005/04/10 20:47:43  gert
 * make do_sanitize() work on a copy of the input line
 * (strtok() modifies the input string, leading to corrupt JOB files)
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>

#include <stdarg.h>

/* globals used by all the routines */
char * program_name;
int    real_user_id;		/* numeric user ID of caller */
char * real_user_name;		/* user name of caller */

int    fax_out_uid;		/* user ID to chown() fax jobs to */
int    fax_out_gid;		/* group ID ... */

#define	ROOT_UID	0	/* root's user ID - override checks */

#define FAX_SEQ_FILE	".Sequence"
#define FAX_SEQ_LOCK	"LCK..seq"

#define MAXJIDLEN	20	/* maximum length of acceptable job ID */

#ifndef MAXPATHLEN
# define MAXPATHLEN 2048
#endif

void error_and_exit( char * string )
{
    fprintf( stderr, "%s: %s\n", program_name, string );
    exit(1);
}

/* generic error messager - just to increase readability of the code below
 */
void eout(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf( stderr, "%s: ", program_name );
    vfprintf( stderr, fmt, ap);
    va_end(ap);
}

/* validate format of job id: "Fnnnnnnn" 
 */
int validate_job_id( char * JobID )
{
    int rc = 0;
    char * p = JobID;

    if ( *p++ != 'F' ) rc = -1;
    while( *p != '\0' && rc == 0 )
    {
	if ( ! isdigit( *p ) ) rc = -1;
	p++;
    }
    if ( strlen( JobID ) > MAXJIDLEN ) rc = -1;

    if ( rc<0 ) eout( "invalid JobID: '%s'\n", JobID );

    return rc;
}

/* verify that a given path name is a directory, and is owned by "fax"
 */
int validate_dir( char * dir )
{
struct stat stb;

    if ( lstat( dir, &stb ) < 0 )
    {
	eout( "can't stat '%s': %s\n", dir, strerror(errno) );
	return -1;
    }
    if ( !S_ISDIR( stb.st_mode ) )
    {
	eout( "%s is no directory!\n", dir );
	return -1;
    }
    if ( stb.st_uid != fax_out_uid )
    {
	eout( "job directory '%s' is not owned by '%s' (%d), abort\n", 
	      dir, FAX_OUT_USER, stb.st_uid );
	return -1;
    }
    return 0;
}

/* lookup user name in ASCII file
 *
 * each line consists of a single user name only
 * if a line is too long (>100 characters) it's silently ignored because
 * it wouldn't match anyway
 *
 * return values: -1 = no such file / error, 0 = not found in file, 1 = found
 *
 * TODO: "man faxspool" claims that "user<blank>otherstuff" is fine
 *       -> either adapt code, or rework documentation
 */

int find_user_in_file( char * file, char * u )
{
FILE * fp;
char buf[100];

    fp = fopen( file, "r" );
    if ( fp == NULL )
    {
	if ( errno != ENOENT )
	    eout( "can't open '%s' for reading: %s\n", file, strerror(errno));
	return -1;
    }

    while( fgets( buf, sizeof(buf)-1, fp ) != NULL )
    {
	int l = strlen(buf);

	/* lines that are too long are just ignored */
	if ( l>0 && buf[l-1] == '\n' )
	{
	    buf[l-1]='\0';
	    if ( strcmp( buf, u ) == 0 )
			{ fclose( fp ); return 1; }
	}
    }

    fclose(fp);
    return 0;
}

/* check whether user may use fax service
 *  - if fax.allow exists, and user is listed -> OK
 *  - if fax.deny exists, and user is not listed -> OK
 *  - if neither exists, and user is root -> OK
 */
int check_fax_allow_deny( char * u )
{
int rc;

    rc = find_user_in_file( FAX_ALLOW, u );
    if ( rc == 1 ) return 0;
    if ( rc == 0 ) 
    {
	eout( "Sorry, %s, you are not allowed to use the fax service.\n", u );
	return -1;
    }

    rc = find_user_in_file( FAX_DENY, u );
    if ( rc == 0 ) return 0;
    if ( rc == 1 ) 
    {
	eout( "Sorry, %s, you are not allowed to use the fax service.\n", u );
	return -1;
    }

    if ( strcmp( u, "root" ) == 0 ) return 0;

    eout( "Neither fax.allow nor fax.deny exist,\n"
	  "so only 'root' may use the fax service. Sorry.\n" );
    return -1;
}

/* create next sequence number
 *   - if sequence file doesn't exist -> create, and return "1"
 *   - if locks/ subdir doesn't exist, create
 *   - lock file by creating hard link
 *   - read current sequence number, add 1, write back
 *   - unlock
 */
long get_next_seq(void)
{
char buf[100];
int try = 0;
long s = -1;
int fd, l;

again:
    if ( link( FAX_SEQ_FILE, FAX_SEQ_LOCK ) < 0 )
    {
	if ( errno == EEXIST )		/* lock exists */
	{
	    if ( ++try < 3 )
	    {
		eout( "sequence file locked (try %d)...\n", try );
		sleep( rand()%3 +1 );
		goto again;
	    }
	    eout( "can't lock sequence file, give up\n" );
	    return -1;
	}

	if ( errno == ENOENT )		/* sequence file does not exist */
	{
	    eout( "sequence file does not exist, creating...\n" );
	    fd = creat( FAX_SEQ_FILE, 0644 );
	    if ( fd < 0 )
	    {
		eout( "can't create sequence file '%s': %s\n",
		      FAX_SEQ_FILE, strerror(errno) );
		return -1;
	    }
	    write( fd, "000000\n", 7 );
	    close( fd );
	    goto again;
	}

	eout( "can't lock sequence file: %s\n", strerror(errno) );
	return -1;
    }

    /* sequence file is locked, now read current sequence */
    fd = open( FAX_SEQ_FILE, O_RDWR );
    if ( fd < 0 )
    {
	eout( "can't open '%s' read/write: %s\n", 
              FAX_SEQ_FILE, strerror(errno) );
	goto unlock_and_out;
    }

    l = read( fd, buf, sizeof(buf)-1 );
    if ( l >= 0 ) buf[l] = '\0';

    if ( l < 0 || l >= sizeof(buf)-1 || ! isdigit( buf[0] ) )
    {
	eout( "sequence file '%s' corrupt\n", FAX_SEQ_FILE );
	goto close_and_out;
    }

    s = atol( buf ) + 1;
    sprintf( buf, "%0*ld\n", l-1, s );

    if ( lseek( fd, 0, SEEK_SET ) != 0 )
    {
	eout( "can't rewind sequence file: %s\n", strerror(errno) );
	goto close_and_out;
    }

    l = strlen(buf);
    if ( write( fd, buf, l ) != l )
    {
	eout( "can't write all %d bytes to %s: %s\n", 
              l, FAX_SEQ_FILE, strerror(errno) );
    }

close_and_out:
    close(fd);

unlock_and_out:
    unlink( FAX_SEQ_LOCK );
    return s;
}

/* create a new job
 *   - check user permissions (fax.allow/fax.deny)
 *   - get next sequence number
 *   - create directory (prefixed with ".in", suffixed with user ID)
 *   - print job ID to stdout
 */
int do_new( void )
{
long seq;
char dirbuf[100];

    /* check if user may use fax service (fax.allow/fax.deny files) */
    if ( check_fax_allow_deny( real_user_name ) < 0 ) return -1;

    /* get next sequence number (including locking) */
    seq = get_next_seq();

    if ( seq <= 0 ) return -1;

    sprintf( dirbuf, ".inF%06ld.%d", seq, real_user_id );

    if ( mkdir(dirbuf, 0700) < 0 )
    {
	eout( "can't create directory '%s': %s\n", dirbuf, strerror(errno) );
	return -1;
    }

    /* print file name (without ".in") to stdout */
    printf( "F%06ld\n", seq );
    return 0;
}

/* do_input
 *  validate job ID and input file name
 *  files with "/" are only allowed in one special case (.source-files/)
 *  read file from stdin, write to $OUT/.in$JID.uid/$filename
 */
int do_input( char * JID, char * outfilename )
{
char * p;
char dir1[MAXJIDLEN+20];
char pathbuf[200], buf[4096];
int fd, r, w;

    if ( isatty(fileno(stdin)) )
	fprintf(stderr, "NOTICE: reading input from stdin, end with ctrl-D\n");

    sprintf( dir1, ".in%s.%d", JID, real_user_id );
    if ( validate_dir( dir1 ) < 0 ) return -1;

    p = outfilename;
    if ( strncmp( outfilename, ".source-files/", 14 ) == 0 )
    {
	p+=14;
	sprintf( pathbuf, "%s/.source-files", dir1 );
	if ( mkdir( pathbuf, 0755 ) < 0 && errno != EEXIST )
	{
	    eout( "can't mkdir '%s': %s\n", pathbuf, strerror(errno));
	    return -1;
	}
    }

    while( *p != '\0' )
    {
	if ( *p == '/' || *p == '\\' || isspace(*p) || !isprint(*p) )
	{
	    eout( "invalid char. '%c' in file name '%s', abort\n",
		  *p, outfilename );
	    return -1;
	}
	p++;
    }

    if ( strlen( dir1 ) + strlen( outfilename ) >= sizeof(pathbuf) -3 )
    {
	eout( "'%s/%s': file name too long\n" ); return -1;
    }

    sprintf( pathbuf, "%s/%s", dir1, outfilename );

    fd = open( pathbuf, O_WRONLY | O_CREAT | O_EXCL, 0644 );
    if ( fd < 0 )
    {
	eout( "can't open '%s' for writing: %s\n", pathbuf, strerror(errno));
	return -1;
    }

    while( ( r = read( fileno(stdin), buf, sizeof(buf) ) ) > 0 )
    {
	w = write( fd, buf, r );
	if ( w != r ) 
	{
	    eout( "can't write all %d bytes to %s: %s\n", 
		  r, pathbuf, strerror(errno) );
	    break;
	}
    }

    if ( r != 0 )	/* read or write error */
    {
	if ( r < 0 )
	    eout( "error reading from stdin: %s\n", strerror(errno));
	close(fd);
	unlink(pathbuf);
	return -1;
    }

    close(fd);
    return 0;
}

/* do a "rm -rf <dir>"
 * TODO: check for ownership?
 */
int recursive_rm( char * dir )
{
char pathbuf[MAXPATHLEN];
DIR * dirp;
struct dirent * de;
struct stat stb;
int rc = 0;

    if ( ( dirp = opendir( dir ) ) == NULL )
    {
	eout( "can't read directory '%s': %s\n", dir, strerror(errno));
	return -1;
    }

    while( ( de = readdir( dirp ) ) != NULL )
    {
	if ( strcmp( de->d_name, "." ) == 0 || 
	     strcmp( de->d_name, ".." ) == 0 )
	{
	    continue;
	}
	if ( strlen( dir ) + strlen( de->d_name ) > sizeof(pathbuf) -5 )
	{
	    eout( "file path too long: %s/%s\n", dir, de->d_name );
	    rc--;
	    continue;
	}
	sprintf( pathbuf, "%s/%s", dir, de->d_name );

	/* fprintf( stderr, "debug2: '%s'\n", pathbuf ); */

	if ( lstat( pathbuf, &stb ) < 0 )
	{
	    eout( "can't stat '%s': %s\n", pathbuf, strerror(errno));
	    rc--;
	    continue;
	}

	/* directories are followed, everything else is removed */
	if ( S_ISDIR( stb.st_mode ) )
	{
	    rc += recursive_rm( pathbuf );
	}
	else
	{
	    if ( unlink( pathbuf ) < 0 )
	    {
		eout( "can't unlink '%s': %s\n", pathbuf, strerror( errno ));
		rc--;
	    }
	}
    }
    closedir( dirp );

    if ( rmdir( dir ) < 0 )
    {
	eout( "can't rmdir '%s': %s\n", dir, strerror(errno));
	rc--;
    }

    return rc;
}


/* make sure that all path names in the following list (separated by
 * whitespace) are local to this directory, exist, and are regular files
 */
int do_sanitize_page_files( char * dir, char * filelist )
{
char * p, * copy, tmp[300];
struct stat stb;
int n=0;
int l;

    l = strlen(filelist);
    if ( l == 0 ) return 0;		/* empty list is OK */

    copy = malloc( l+1 );
    if ( copy == NULL )
    {
	eout( "in do_sanitize: cannot malloc() %d bytes, abort\n", l ); return -1;
    }
    memcpy( copy, filelist, l+1 );

    p = strtok( copy, " \t\n" );

    while( p != NULL )
    {
	if ( strchr( p, '/' ) != NULL )
	{
	    eout( "non-local file name: '%s', abort\n", p ); return -1;
	}

	if ( strlen( dir ) + strlen( p ) + 3 >= sizeof(tmp) )
	{
	    eout( "file name '%s' too long, abort\n", p ); return -1;
	}
	sprintf( tmp, "%s/%s", dir, p );

	if ( lstat( tmp, &stb ) < 0 )
	{
	    eout( "can't stat file '%s': %s\n", tmp, strerror(errno) );
	    return -1;
	}

	if ( !S_ISREG( stb.st_mode ) )
	{
	    eout( "'%s' is not a regular file, abort\n", tmp ); return -1;
	}

	n++;
	p = strtok( NULL, " \t\n" );
    }

    return n;
}

/* Activate "pending" fax job
 *
 */
int do_activate( char * JID )
{
char dir1[MAXJIDLEN+20];
char buf[1000], *p, *q;
int fd;
int user_seen = 0;

    if ( isatty(fileno(stdin)) )
	fprintf(stderr, "NOTICE: reading input from stdin, end with ctrl-D\n");

    sprintf( dir1, ".in%s.%d", JID, real_user_id );
    if ( validate_dir( dir1 ) < 0 ) return -1;

    sprintf( buf, "%s/JOB", dir1 );

    /* the JOB file has to be world-readable, relax umask */
    umask( 0022 );

/* TODO: check if this portably catches symlinks to non-existant files! */
    if ( ( fd = open( buf, O_WRONLY | O_CREAT | O_EXCL, 0644 ) ) < 0 )
    {
	eout( "can't create JOB file '%s': %s\n", buf, strerror(errno) );
	recursive_rm(dir1);
	return -1;
    }

    /* read queue metadata from stdin, sanitize, write to JOB fd */
    while( ( p = fgets( buf, sizeof(buf)-1, stdin ) ) != NULL )
    {
	int l = strlen(buf);

	if ( l >= sizeof(buf)-2 )
	{
	    eout( "input line too long\n" ); break;
	}

	if ( l>0 && buf[l-1] == '\n' ) buf[--l]='\0';

	if ( strncmp(buf, "user ", 5) == 0 )
	{
	    user_seen=1;
	    if ( real_user_id != ROOT_UID &&
		 strcmp( buf+5, real_user_name ) != 0 )
	    {
		eout( "user name mismatch (%s <-> %s)\n", buf+5, real_user_name );
		break;
	    }
	}
	if ( strncmp(buf, "pages", 5 ) == 0 &&
	     do_sanitize_page_files( dir1, buf+5 ) < 0 )
	{
	    eout( "bad input files specified\n" );
	    break;
	}

	/* replace all quote characters, backslash and ';' by '_' */
	for( q = buf; *q != '\0'; q++ )
	{
	    if ( *q == '\'' || *q == '"' || *q == '`' || 
		 *q == '\\' || *q == ';' )
				    { *q = '_'; }
	}

        /* and write to JOB file... */
	buf[l++] = '\n';
	if ( write( fd, buf, l ) != l )
	{
	    eout( "can't write line to JOB file: %s\n", strerror(errno) );
	    break;
	}
    }

    if ( p != NULL )	/* loop aborted */
    {
        close(fd); recursive_rm(dir1); return -1;
    }

    if ( !user_seen )		/* no "user ..." line in JOB? */
    {
	sprintf( buf, "user %.100s\n", real_user_name );
	write( fd, buf, strlen(buf) );
    }
    close(fd);

    /* now make directory world-readable & move to final place */
    if ( chmod( dir1, 0755 ) < 0 )
    {
	eout( "can't chmod '%s' to 0755: %s\n", dir1, strerror(errno));
	recursive_rm(dir1); return -1;
    }

    if ( rename( dir1, JID ) < 0 )
    {
	eout( "can't rename '%s' to '%s': %s\n", dir1, JID, strerror(errno));
	recursive_rm(dir1); return -1;
    }

    return 0;
}


/* helper function for do_remove and do_requeue
 *  - check whether /$JID/ exists at all (and is a directory)
 *  - lock $JID/$jobfile, if present
 *  - check $JID/$jobfile for "user xxx" and compare with caller uid
 *
 * TODO: permit "root" override
 */
int check_user_perms( char * JID, char * jobfile )
{
struct stat stb;
char buf[1000], *p;
FILE * fp;
char jfile[MAXJIDLEN+30], lfile[MAXJIDLEN+30];

    if ( lstat( JID, &stb ) < 0 ||
	 !S_ISDIR( stb.st_mode ) ||
	 stb.st_uid != fax_out_uid )
    {
	eout( "'%s' is not a directory or has wrong owner\n", JID );
	return -1;
    }

    sprintf( jfile, "%s/%s", JID, jobfile );
    sprintf( lfile, "%s/%s", JID, "JOB.locked" );

    if ( link( jfile, lfile ) < 0 )
    {
	if ( errno == EEXIST )
	{
	    eout( "%s already locked\n", jfile ); return -1;
	}
	if ( errno == ENOENT )
	{
	    return -2;		/* signal "file not found" to caller */
	}

	eout( "can't lock JOB file: %s\n", strerror(errno) ); return -1;
    }

    if ( ( fp = fopen( jfile, "r" ) ) == NULL )
    {
	eout( "can't open '%s' for reading: %s\n", jfile, strerror(errno) );
	unlink( lfile );
	return -1;
    }

    while( ( p = fgets( buf, sizeof(buf)-1, fp ) ) != NULL )
    {
	int l = strlen(buf);

	if ( l >= sizeof(buf)-2 )
	{
	    eout( "input line too long\n" ); 
	    unlink( lfile );
	    fclose(fp);
	    return -1;
	}

	if ( l>0 && buf[l-1] == '\n' ) buf[--l]='\0';

	if ( strncmp(buf, "user ", 5) == 0 )
	{
	    if ( real_user_id != ROOT_UID &&
		 strcmp( buf+5, real_user_name ) != 0 )
	    {
		fprintf( stderr, "%s: not your job, can't do anything (%s <-> %s)\n", jfile, buf+5, real_user_name );
		unlink( lfile );
		fclose(fp);
		return -1;
	    }
	}
    }

    fclose(fp);
    return 0;		/* lock file purposely kept in place! */
}

int do_remove( char * JID )
{
int rc;

    rc = check_user_perms( JID, "JOB" );
    if ( rc == -2 )				/* not found */
	rc = check_user_perms( JID, "JOB.error" );
    if ( rc == -2 )				/* not found */
	rc = check_user_perms( JID, "JOB.suspended" );
    if ( rc == -2 )				/* not found */
	rc = check_user_perms( JID, "JOB.done" );

    if ( rc < 0 )				/* check failed */
    {
	if ( rc == -2 )				/* still not found */
	    eout( "no JOB file in %s/ - can't verify permissions\n", JID );
	return -1;
    }

    rc = recursive_rm( JID );

    if ( rc < 0 )
    {
	eout( "could not remove %d files or subdirectories\n", -rc );
	return -1;
    }
    return 0;
}

int do_requeue( char * JID )
{
int rc, fd; 
char file1[MAXJIDLEN+30], file2[MAXJIDLEN+30];
char buf[100];
time_t ti;

    rc = check_user_perms( JID, "JOB.suspended" );
    if ( rc == -2 )
    {
	eout( "no %s/JOB.suspended found, do nothing\n", JID );
	return -1;
    }
    if ( rc < 0 ) { return -1; }

    /* JOB.suspended found, and user permissions OK */

    sprintf( file1, "%s/JOB.suspended", JID );
    sprintf( file2, "%s/JOB", JID );

    if ( ( fd = open( file1, O_WRONLY | O_APPEND ) ) < 0 )
    {
	eout( "can't open '%s' to append status line: %s\n", 
	      file1, strerror(errno));
	return -1;
    }

    time(&ti);
    sprintf( buf, "Status %.40s", ctime(&ti) );
    sprintf( &buf[strlen(buf)-1], " - reactivated by %.16s\n", real_user_name);

    rc = strlen(buf);
    if ( write( fd, buf, rc ) != rc )
    {
	eout( "can't write all %d bytes to '%s': %s\n",
	       rc, file1, strerror(errno) );
	close( fd );
	return -1;
    }
    close( fd );

    if ( rename( file1, file2 ) < 0 )
    {
	eout( "can't rename '%s' to '%s': %s\n", 
	      file1, file2, strerror(errno) );
	return -1;
    }

    sprintf( file1, "%s/JOB.locked", JID );

    if ( unlink( file1 ) < 0 )
    {
	eout( "can't unlink '%s': %s\n", file1, strerror(errno) );
    }

    /* signal to faxrunqd that queue needs re-reading */
    fd = open( ".queue-changed", O_WRONLY | O_CREAT | O_EXCL, 0644 );
    if ( fd < 0 )
    {
	if ( errno != EEXIST )
	    eout( "can't create '.queue-changed' file: %s\n", strerror(errno));
    }
    else 
	close(fd);

    return 0;
}

int main( int argc, char ** argv )
{
    struct passwd * pw; 		/* for user name */
    struct stat stb;

    program_name = strrchr( argv[0], '/' );
    if ( program_name != NULL ) program_name++;
		           else program_name = argv[0];

    if ( argc < 2 )
	{ error_and_exit( "keyword missing" ); }

    /* common things to check and prepare */

    /* make sure people do not play umask tricks on us - the only
     * bits that are accepted in a user umask are "044" - permit/prevent 
     * read access by group/other.  Write access is always denied.
     */
    umask( ( umask(0) & 0044 ) | 0022 );

    /* get numeric uid/gid for fax user */
    pw = getpwnam( FAX_OUT_USER );
    if ( pw == NULL )
    {
	eout( "can't get user ID for user '%s', abort!\n", FAX_OUT_USER );
	exit(3);
    }
    fax_out_uid = pw->pw_uid;
    fax_out_gid = pw->pw_gid;

    /* effective user ID is root, real user ID is still the caller's */
    if ( geteuid() != fax_out_uid )
    {
	eout( "must be set-uid '%s'\n", FAX_OUT_USER );
	exit(3);
    }
    real_user_id = getuid();
    pw = getpwuid( real_user_id );
    if ( pw == NULL || pw->pw_name == NULL )
    {
	eout( "you don't exist, go away (uid=%d)!\n", real_user_id );
	exit(3);
    }
    real_user_name = pw->pw_name;

    /* spool directory has to exist, and should be owned by 'fax' */
    if ( chdir( FAX_SPOOL_OUT ) < 0 )
    {   
	eout( "can't chdir to %s: %s\n", FAX_SPOOL_OUT, strerror(errno) );
	exit(2);
    }
    if ( stat( ".", &stb ) < 0 )
    {
	eout( "can't stat %s: %s\n", FAX_SPOOL_OUT, strerror(errno) );
	exit(2);
    }
    if ( ( stb.st_mode & 0022 ) > 0 ) 
    {
	eout( "WARNING: %s is group- or world-writeable\n", FAX_SPOOL_OUT);
    }
    if ( stb.st_uid != fax_out_uid )
    {
	eout( "WARNING: %s should be owned by user '%s'\n",
	      FAX_SPOOL_OUT, FAX_OUT_USER );
    }

    /* now parse arguments and go to specific functions */
    if ( argc == 2 && strcmp( argv[1], "new" ) == 0 ) 
    {
	exit( do_new() <0? 10: 0);
    }
    if ( argc == 4 && strcmp( argv[1], "input" ) == 0 )
    {
	/* second parameter is job ID, 3rd is file name */
	char * job_id = argv[2];
	char * file_name = argv[3];
	if ( validate_job_id( job_id ) <0 ) exit(1);

	exit( do_input( job_id, file_name ) <0? 10: 0);
    }
    if ( argc == 3 )
    {
	/* second parameter is common for all commands: job ID */
	char * job_id = argv[2];
	if ( validate_job_id( job_id ) <0 ) exit(1);

    	if( strcmp( argv[1], "activate" ) == 0 )
	{
	    exit( do_activate( job_id ) <0? 10: 0);
	}
	if ( strcmp( argv[1], "remove" ) == 0 )
	{
	    exit( do_remove( job_id ) <0? 10: 0);
	}
	if ( strcmp( argv[1], "requeue" ) == 0 )
	{
	    exit( do_requeue( job_id ) <0? 10: 0);
	}
    }

    error_and_exit( "invalid keyword or wrong number of parameters" );
    return 0;
}
