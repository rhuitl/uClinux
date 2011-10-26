#ident "$Id: locks.c,v 4.4 2001/01/01 13:26:00 gert Exp $ Copyright (c) Gert Doering / Paul Sutcliffe Jr."

/* large parts of the code in this module are taken from the
 * "getty kit 2.0" by Paul Sutcliffe, Jr., paul@devon.lns.pa.us,
 * and are used with permission here.
 * SVR4 style locking by Bodo Bauer, bodo@hal.nbg.sub.org.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

/* some OSes do include this in stdio.h, others don't... */
#ifndef EEXIST
#include <errno.h>
#endif

#include "mgetty.h"
#include "policy.h"

/* SVR4 uses a different locking mechanism. This is why we need this... */
#ifdef SVR4 
#include <sys/mkdev.h>
 
#define LCK_NODEV    -1
#define LCK_OPNFAIL  -2
#endif

       char	lock[MAXLINE+1];	/* name of the lockfile */

static int readlock _PROTO(( char * name ));
static char *  get_lock_name _PROTO(( char * lock_name, char * device ));
static int lock_write_pid _PROTO(( int fd ));
static int we_have_lock = FALSE;

/*
 *	do_makelock() - attempt to create a lockfile
 *
 *	Returns FAIL if lock could not be made (line in use).
 */

int do_makelock _P0( void )
{
	int fd, pid;
	char *temp, buf[MAXLINE+1];
	int tries = 0;

	we_have_lock = FALSE;

	lprintf( L_NOISE, "do_makelock: lock='%s'", lock );

	/* first make a temp file */

#ifdef HAVE_MKSTEMP
	/* secure, but not as portable */
	temp=buf;
	sprintf(buf, LOCK, "TM.XXXXXX");
	if ((fd = mkstemp(temp)) == FAIL ) {
		lprintf(L_ERROR, "cannot create tempfile (%s)", temp);
		return(FAIL);
	}
#else
	/* portable, but subject to some problems on some platforms */
again:
	sprintf(buf, LOCK, "TM.XXXXXX");
	temp = mktemp(buf);
	unlink(temp);
	if ((fd = open(temp, O_CREAT|O_WRONLY|O_EXCL, 0644)) == FAIL) {
		lprintf(L_ERROR, "cannot create tempfile (%s)", temp);
		if ( errno == EEXIST && ++tries < 20 ) goto again;
		return(FAIL);
	}
#endif

	/* just in case some "umask" is set (errors are ignored) */
	chmod( temp, 0644 );

	/* put my pid in it */
	if ( lock_write_pid( fd ) == FAIL)
	                        { unlink(temp); return FAIL; }

	/* link it to the lock file */

	while (link(temp, lock) == FAIL)
	{
	        if (errno != EEXIST )
		{
		    lprintf(L_ERROR, "lock not made: link(temp,lock) failed" );
		}

		if (errno == EEXIST)		/* lock file already there */
		{
		    if ((pid = readlock(lock)) == FAIL)
		    {
			if ( errno == ENOENT )	/* disappeared */
			    continue;
			else
			{
			    lprintf( L_NOISE, "cannot read lockfile" );
			    unlink(temp);
			    return FAIL;
			}
		    }

		    if (pid == getpid())	/* huh? WE locked the line!*/
		    {
			lprintf( L_WARN, "we *have* the line!" );
			break;
		    }

		    if ((kill(pid, 0) == FAIL) && errno == ESRCH)
		    {
			/* pid that created lockfile is gone */
			lprintf( L_NOISE, "stale lockfile, created by process %d, ignoring", pid );
			if ( unlink(lock) < 0 &&
			         errno != EINTR && errno != ENOENT )
			{
			    lprintf( L_ERROR, "unlink() failed, giving up" );
			    unlink(temp);
			    return FAIL;
			}
			continue;
		    }
		    
		    lprintf(L_MESG, "lock not made: lock file exists (pid=%d)", pid);
		}				/* if (errno == EEXIST) */
		
		(void) unlink(temp);
		return(FAIL);
	}
	
	lprintf(L_NOISE, "lock made");
	(void) unlink(temp);
	we_have_lock = TRUE;
	return(SUCCESS);
}

/* makelock( Device )
 *
 * lock a device,
 * using the LOCK directory from mgetty.c resp. get_lock_name()
 */

int makelock _P1( (device),
		  char *device)
{
    lprintf(L_NOISE, "makelock(%s) called", device);

    if ( get_lock_name( lock, device ) == NULL )
    {
	lprintf( L_ERROR, "cannot get lock name" );
	return FAIL;
    }

    return do_makelock();
}

/* steal_lock( device, process id )
 *
 * steal a lock file from process "id", used for callback handover
 */
int steal_lock _P2((device, pid), char * device, int pid )
{
    int retcode, is_pid, fd;
    
    lprintf(L_NOISE, "steal_lock(%s) called", device);

    if ( get_lock_name( lock, device ) == NULL )
    {
	lprintf( L_ERROR, "cannot get lock name" );
	return FAIL;
    }

    is_pid = readlock(lock);

    if ( is_pid != pid )
    {
	lprintf( L_ERROR, "PIDs do not match, lock process is %d, should be %d", is_pid, pid );
	return FAIL;
    }

    /*!!! FIXME: there is a race condition here (is it?) */
    fd = open( lock, O_RDWR );

    if ( fd < 0 )
    {
	lprintf( L_ERROR, "can't open %d for read/write" );
	return FAIL;
    }

    retcode = lock_write_pid( fd );

    if ( retcode == SUCCESS ) we_have_lock = TRUE;
    return retcode;
}

/* makelock_file( lock file )
 *
 * make a lock file with a given name (used for locking of other files
 * than device nodes)
 */

int makelock_file _P1( (file), char * file )
{
    lprintf(L_NOISE, "makelock_file(%s) called", file);

    strcpy( lock, file );
    
    return do_makelock();
}
   
/*
 *	checklock() - test for presence of valid lock file
 *
 *	if lockfile found, return PID of process holding it, 0 otherwise
 */

int checklock _P1( (device), char * device)
{
    int pid;
    struct stat st;
    char name[MAXLINE+1];
    
    if ( get_lock_name( name, device ) == NULL )
    {
	lprintf( L_ERROR, "cannot get lock name" );
	return NO_LOCK;
    }

    if ((stat(name, &st) == FAIL) && errno == ENOENT)
    {
	lprintf(L_NOISE, "checklock: stat failed, no file");
	return NO_LOCK;
    }
    
    if ((pid = readlock(name)) == FAIL)
    {
	lprintf(L_MESG, "checklock: couldn't read lockfile");
	return NO_LOCK;
    }

    if (pid == getpid())
    {
	lprintf(L_WARN, "huh? It's *our* lock file!" );
	return NO_LOCK;
    }
		
    if ((kill(pid, 0) == FAIL) && errno == ESRCH)
    {
	lprintf(L_NOISE, "checklock: no active process has lock, will remove");
	(void) unlink(name);
	return NO_LOCK;
    }
    
    lprintf(L_NOISE, "lockfile found, pid=%d", pid );
    
    return pid;
}

/*
 *	readlock() - read contents of lockfile
 *
 *	Returns pid read or FAIL on error.
 *
 *      private function
 */

static int readlock _P1( (name),
			 char * name )
{
	int fd, pid;
	char apid[20];
	int  length;

	if ((fd = open(name, O_RDONLY)) == FAIL)
		return(FAIL);

	length = read(fd, apid, sizeof(apid)-1);
	apid[length]=0;		/* make sscanf() happy */

	pid = 0;
	if ( length == sizeof( pid ) || sscanf(apid, "%d", &pid) != 1 ||
	     pid == 0 )
	{
	    pid = * ( (int *) apid );
#if LOCKS_BINARY == 0
	    lprintf( L_WARN, "compiled with ascii locks, found binary lock file (length=%d, pid=%d)!", length, pid );
#endif
	}
#if LOCKS_BINARY == 1
	else
	{
	    lprintf( L_WARN, "compiled with binary locks, found ascii lock file (length=%d, pid=%d)!", length, pid );
	}
#endif

	(void) close(fd);
	return(pid);
}

/* lock_write_pid()
 *
 * write contents of lock file: my process ID in specified format
 *
 * private function
 */
static int lock_write_pid _P1((fd), int fd)
{
#if LOCKS_BINARY
    int bpid;			/* must be 4 bytes wide! */
    bpid = getpid();
    if ( write(fd, &bpid, sizeof(bpid) ) != sizeof(bpid) )
#else
    char apid[16];
    sprintf( apid, "%10d\n", (int) getpid() );
    if ( write(fd, apid, strlen(apid)) != strlen(apid) )
#endif
    {
	lprintf( L_FATAL, "cannot write PID to (temp) lock file" );
	close(fd);
	return(FAIL);
    }
    close(fd);
    return SUCCESS;
}
	
/*
 *	rmlocks() - remove lockfile
 */

RETSIGTYPE rmlocks(SIG_HDLR_ARGS)
{
    if ( we_have_lock )
    {
	lprintf( L_NOISE, "removing lock file" );
	if ( unlink(lock) == -1 )
	    lprintf( L_ERROR, "error removing lock file (huh?!)" );
    }
    /* mark lock file as 'not set' */
    we_have_lock = FALSE;
}

/* get_lock_name()
 *
 * determine full path + name of the lock file for a given device
 */

#ifdef SVR4

/*
 * get_lock_name() - create SVR4 lock file name (Bodo Bauer)
 */

static char *get_lock_name _P2( (lock, fax_tty),
			 char* lock, char* fax_tty )
{
  struct stat tbuf;
  char ttyname[FILENAME_MAX];

  lprintf(L_NOISE, "get_lock_name(%s) called", fax_tty);

  if ( strncmp( fax_tty, "/dev/", 5 ) == 0 )
      strcpy( ttyname, fax_tty );
  else
      sprintf(ttyname, "/dev/%s", fax_tty);
  
  lprintf(L_NOISE, "-> ttyname %s", ttyname);

  if (stat(ttyname, &tbuf) < 0) {
    if(errno == ENOENT) {
      lprintf(L_NOISE, "device does not exist: %s", ttyname);
      return(NULL);		
    } else {
      lprintf(L_NOISE, "could not access line: %s", ttyname);
      return(NULL);		
    }
  }

  sprintf(lock,"%s/LK.%03u.%03u.%03u",
	  LOCK_PATH,
	  major(tbuf.st_dev),
	  tbuf.st_rdev >> 18, 
	  minor(tbuf.st_rdev));

  lprintf(L_NOISE, "lock file: %s", lock);
  return(lock);
}

#else	/* not SVR4 */ 

static char * get_lock_name _P2( (lock_name, device),
			  char * lock_name, char * device )
{
#ifdef LOCKS_LOWERCASE
    /* sco locking convention -> change all device names to lowercase */

    char p[MAXLINE+1];
    int i;
    if ( ( i = strlen( device ) ) > sizeof(p) )
    {
	lprintf( L_FATAL, "get_lock_name: device name too long" );
	exit(5);
    }
    
#ifdef LOCKS_ALL_LOWERCASE
    /* convert the full name */
    while ( i >= 0 )
    {
	p[i] = tolower( device[i] ); i--;
    }
#else
    /* convert only the last character */
    strcpy( p, device );
    i--;
    p[i] = tolower( p[i] );
#endif
    
    device = p;
#endif	/* LOCKS_LOWERCASE */

    /* throw out all directory prefixes */
    if ( strchr( device, '/' ) != NULL )
        device = strrchr( device, '/' ) +1;
    
    sprintf( lock_name, LOCK, device);

    return lock_name;
}
	
#endif /* !SVR4 */
