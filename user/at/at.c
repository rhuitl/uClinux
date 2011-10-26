/* 
 *  at.c : Put file into atrun queue
 *  Copyright (C) 1993, 1994, 1995, 1996, 1997 Thomas Koenig
 *
 *  Atrun & Atq modifications
 *  Copyright (C) 1993  David Parsons
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, 
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* System Headers */

#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <ctype.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#elif HAVE_SYS_DIRENT_H
#include <sys/dirent.h>
#elif HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#elif defined(HAVE_SYS_FCNTL_H)
#include <sys/fcntl.h>
#endif

#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#else
#include <time.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Local headers */

#include "at.h"
#include "panic.h"
#include "parsetime.h"
#include "perm.h"

#include "privs.h"

/* Macros */

#ifndef ATJOB_MX
#define ATJOB_MX 255
#endif

#define ALARMC 10		/* Number of seconds to wait for timeout */

#define SIZE 255

#define TIMEFORMAT_POSIX	"%a %b %e %T %Y"
#define TIMEFORMAT_ISO		"%Y-%m-%d %H:%M"
#define TIMESIZE	50

enum {
    ATQ, BATCH, ATRM, AT, CAT
};				/* what program we want to run */

/* Global variables */

uid_t real_uid, effective_uid;
gid_t real_gid, effective_gid;

uid_t daemon_uid = (uid_t) - 3;
gid_t daemon_gid = (gid_t) - 3;

/* File scope variables */

static char rcsid[] = "$Id: at.c,v 1.28 1997/05/26 08:31:34 ig25 Exp ig25 $";
char *no_export[] =
{
    "TERM", "DISPLAY", "_", "SHELLOPTS"
};
static int send_mail = 0;

/* External variables */

extern char **environ;
int fcreated;
char *namep;
char atfile[] = ATJOB_DIR "/12345678901234";

char *atinput = (char *) 0;	/* where to get input from */
char atqueue = 0;		/* which queue to examine for jobs (atq) */
char atverify = 0;		/* verify time instead of queuing job */

/* Function declarations */

static void sigc(int signo);
static void alarmc(int signo);
static char *cwdname(void);
static void writefile(time_t runtimer, char queue);
static void list_jobs(void);

/* Signal catching functions */

static RETSIGTYPE 
sigc(int signo)
{
/* If the user presses ^C, remove the spool file and exit 
 */
    if (fcreated) {
	PRIV_START
	    unlink(atfile);
	PRIV_END
    }
    exit(EXIT_FAILURE);
}

static void 
alarmc(int signo)
{
/* Time out after some seconds
 */
    panic("File locking timed out");
}

/* Local functions */

static char *
cwdname(void)
{
/* Read in the current directory; the name will be overwritten on
 * subsequent calls.
 */
    static char *ptr = NULL;
    static size_t size = SIZE;

    if (ptr == NULL)
	ptr = (char *) mymalloc(size);

    while (1) {
	if (ptr == NULL)
	    panic("Out of memory");

	if (getcwd(ptr, size - 1) != NULL)
	    return ptr;

	if (errno != ERANGE)
	    perr("Cannot get current working directory");

	free(ptr);
	size += SIZE;
	ptr = (char *) mymalloc(size);
    }
}

static long
nextjob()
{
    long jobno;
    FILE *fid;

    jobno = 0;
    fid = fopen(LFILE, "r+");
    if (fid != NULL) {
	fscanf(fid, "%5lx", &jobno);
	rewind(fid);
    } else {
	fid = fopen(ATJOB_DIR "/.SEQ", "w");
	if (fid == NULL)
	    return EOF;
    }
    jobno = (1 + jobno) % 0xfffff;	/* 2^20 jobs enough? */
    fprintf(fid, "%05lx\n", jobno);

    fclose(fid);
    return jobno;
}

static void
writefile(time_t runtimer, char queue)
{
/* This does most of the work if at or batch are invoked for writing a job.
 */
    long jobno;
    char *ap, *ppos, *mailname;
    struct passwd *pass_entry;
    struct stat statbuf;
    int fd, lockdes, fd2;
    FILE *fp, *fpin;
    struct sigaction act;
    char **atenv;
    int ch;
    mode_t cmask;
    struct flock lock;
    struct tm *runtime;
    char timestr[TIMESIZE];
    pid_t pid;
    int istty;
    int kill_errno;

/* Install the signal handler for SIGINT; terminate after removing the
 * spool file if necessary
 */
    act.sa_handler = sigc;
    sigemptyset(&(act.sa_mask));
    act.sa_flags = 0;

    sigaction(SIGINT, &act, NULL);

    ppos = atfile + strlen(ATJOB_DIR) + 1;

    /* Loop over all possible file names for running something at this
     * particular time, see if a file is there; the first empty slot at any
     * particular time is used.  Lock the file LFILE first to make sure
     * we're alone when doing this.
     */

    PRIV_START

	if ((lockdes = open(LFILE, O_WRONLY)) < 0)
	    perr("Cannot open lockfile " LFILE);

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	act.sa_handler = alarmc;
	sigemptyset(&(act.sa_mask));
	act.sa_flags = 0;

	/* Set an alarm so a timeout occurs after ALARMC seconds, in case
	 * something is seriously broken.
	 */
	sigaction(SIGALRM, &act, NULL);
	alarm(ALARMC);
	fcntl(lockdes, F_SETLKW, &lock);
	alarm(0);

	if ((jobno = nextjob()) == EOF)
	    perr("Cannot generate job number");

	sprintf(ppos, "%c%5lx%8lx", queue,
		jobno, (unsigned long) (runtimer / 60));

	for (ap = ppos; *ap != '\0'; ap++)
	    if (*ap == ' ')
		*ap = '0';

	if (stat(atfile, &statbuf) != 0)
	    if (errno != ENOENT)
		perr("Cannot access " ATJOB_DIR);

	/* Create the file. The x bit is only going to be set after it has
	 * been completely written out, to make sure it is not executed in the
	 * meantime.  To make sure they do not get deleted, turn off their r
	 * bit.  Yes, this is a kluge.
	 */
	cmask = umask(S_IRUSR | S_IWUSR | S_IXUSR);
	if ((fd = creat(atfile, O_WRONLY)) == -1)
	    perr("Cannot create atjob file %.500s", atfile);

	if ((fd2 = dup(fd)) < 0)
	    perr("Error in dup() of job file");

	if (fchown(fd2, real_uid, real_gid) != 0)
	    perr("Cannot give away file");

    PRIV_END

    /* We no longer need suid root; now we just need to be able to write
     * to the directory, if necessary.
     */

    REDUCE_PRIV(daemon_uid, daemon_gid)
    /* We've successfully created the file; let's set the flag so it 
     * gets removed in case of an interrupt or error.
     */
    fcreated = 1;

    /* Now we can release the lock, so other people can access it
     */
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    fcntl(lockdes, F_SETLKW, &lock);
    close(lockdes);

    if ((fp = fdopen(fd, "w")) == NULL)
	panic("Cannot reopen atjob file");

    /* Get the userid to mail to, first by trying getlogin(), which reads
     * /var/run/utmp, then from LOGNAME, finally from getpwuid().
     */
    mailname = getlogin();
    if (mailname == NULL)
	mailname = getenv("LOGNAME");

    if ((mailname == NULL) || (mailname[0] == '\0')
	|| (strlen(mailname) > 8) || (getpwnam(mailname) == NULL)) {
	pass_entry = getpwuid(real_uid);
	if (pass_entry != NULL)
	    mailname = pass_entry->pw_name;
    }
    if (atinput != (char *) NULL) {
	fpin = freopen(atinput, "r", stdin);
	if (fpin == NULL)
	    perr("Cannot open input file %.500s", atinput);
    }
    fprintf(fp, "#!/bin/sh\n# atrun uid=%d gid=%d\n# mail %8s %d\n",
	    real_uid, real_gid, mailname, send_mail);

    /* Write out the umask at the time of invocation
     */
    fprintf(fp, "umask %lo\n", (unsigned long) cmask);

    /* Write out the environment. Anything that may look like a
     * special character to the shell is quoted, except for \n, which is
     * done with a pair of ""'s.  Dont't export the no_export list (such
     * as TERM or DISPLAY) because we don't want these.
     */
    for (atenv = environ; *atenv != NULL; atenv++) {
	int export = 1;
	char *eqp;

	eqp = strchr(*atenv, '=');
	if (ap == NULL)
	    eqp = *atenv;
	else {
	    unsigned int i;
	    for (i = 0; i < sizeof(no_export) / sizeof(no_export[0]); i++) {
		export = export
		    && (strncmp(*atenv, no_export[i],
				(size_t) (eqp - *atenv)) != 0);
	    }
	    eqp++;
	}

	if (export) {
	    fwrite(*atenv, sizeof(char), eqp - *atenv, fp);
	    for (ap = eqp; *ap != '\0'; ap++) {
		if (*ap == '\n')
		    fprintf(fp, "\"\n\"");
		else {
		    if (!isalnum(*ap)) {
			switch (*ap) {
			case '%':
			case '/':
			case '{':
			case '[':
			case ']':
			case '=':
			case '}':
			case '@':
			case '+':
			case '#':
			case ',':
			case '.':
			case ':':
			case '-':
			case '_':
			    break;
			default:
			    fputc('\\', fp);
			    break;
			}
		    }
		    fputc(*ap, fp);
		}
	    }
	    fputs("; export ", fp);
	    fwrite(*atenv, sizeof(char), eqp - *atenv - 1, fp);
	    fputc('\n', fp);

	}
    }
    /* Cd to the directory at the time and write out all the
     * commands the user supplies from stdin.
     */
    fprintf(fp, "cd ");
    for (ap = cwdname(); *ap != '\0'; ap++) {
	if (*ap == '\n')
	    fprintf(fp, "\"\n\"");
	else {
	    if (*ap != '/' && !isalnum(*ap))
		fputc('\\', fp);

	    fputc(*ap, fp);
	}
    }
    /* Test cd's exit status: die if the original directory has been
     * removed, become unreadable or whatever
     */
    fprintf(fp, " || {\n\t echo 'Execution directory "
	    "inaccessible' >&2\n\t exit 1\n}\n");

    istty = isatty(fileno(stdin));
    if (istty) {
	fprintf(stderr, "at> ");
	fflush(stderr);
    }
    while ((ch = getchar()) != EOF) {
	fputc(ch, fp);
	if (ch == '\n' && istty) {
	    fprintf(stderr, "at> ");
	    fflush(stderr);
	}
    }
    if (istty) {
	fprintf(stderr, "<EOT>\n");
    }
    fprintf(fp, "\n");
    if (ferror(fp))
	panic("Output error");

    if (ferror(stdin))
	panic("Input error");

    fclose(fp);

    /* Set the x bit so that we're ready to start executing
     */

    if (fchmod(fd2, S_IRUSR | S_IWUSR | S_IXUSR) < 0)
	perr("Cannot give away file");

    close(fd2);

    /* POSIX.2 allows the shell specified by the user's SHELL environment
       variable, the login shell from the user's password database entry,
       or /bin/sh to be the command interpreter that processes the at-job.
       It also alows a warning diagnostic to be printed.  Because of the
       possible variance, we always output the diagnostic. */

    fprintf(stderr, "warning: commands will be executed using /bin/sh\n");

    runtime = localtime(&runtimer);

    /* We only use the sick POSIX time format if POSIXLY_CORRECT
       is set.  Otherwise, we use ISO format.
     */

    if (getenv("POSIXLY_CORRECT") != NULL) {
	strftime(timestr, TIMESIZE, TIMEFORMAT_POSIX, runtime);
    } else {
	strftime(timestr, TIMESIZE, TIMEFORMAT_ISO, runtime);
    }
    fprintf(stderr, "job %ld at %s\n", jobno, timestr);

    /* Signal atd, if present. Usual precautions taken... */
    fd = open(PIDFILE, O_RDONLY);
    if (fd == -1) {
	fprintf(stderr, "Can't open " PIDFILE " to signal atd. No atd running?\n");
	return;
    }

    if (fstat(fd, &statbuf) == -1)
	return;
    if ((statbuf.st_uid != 0) || !S_ISREG(statbuf.st_mode) ||
	(statbuf.st_mode & (S_IWGRP | S_IWOTH)))
	return;

    fp = fdopen(fd, "r");
    if (fp == NULL)
	return;
    if (fscanf(fp, "%d", &pid) != 1)
	return;

    kill_errno = 0;

    PRIV_START
	if (kill(pid, SIGHUP) == -1)
	    kill_errno = errno;
    PRIV_END

	switch (kill_errno) {
    case 0:
	break;

    case EINVAL:
	panic("kill returned EINVAL");
	break;

    case EPERM:
	fprintf(stderr,"Can't signal atd (permission denied)\n");
	break;

    case ESRCH:
	fprintf(stderr, "Warning: at daemon not running\n");
	break;

    default:
	panic("kill returned impossible error number");
	break;
    }
    return;
}

static void
list_jobs()
{
    /* List all a user's jobs in the queue, by looping through ATJOB_DIR, 
     * or everybody's if we are root
     */
    DIR *spool;
    struct dirent *dirent;
    struct stat buf;
    struct tm *runtime;
    unsigned long ctm;
    char queue;
    long jobno;
    time_t runtimer;
    char timestr[TIMESIZE];

    PRIV_START

    if (chdir(ATJOB_DIR) != 0)
	perr("Cannot change to " ATJOB_DIR);

    if ((spool = opendir(".")) == NULL)
	perr("Cannot open " ATJOB_DIR);

    /*  Loop over every file in the directory 
     */
    while ((dirent = readdir(spool)) != NULL) {
	if (stat(dirent->d_name, &buf) != 0)
	    perr("Cannot stat in " ATJOB_DIR);

	/* See it's a regular file and is the user's */
	if (!S_ISREG(buf.st_mode)
	    || ((buf.st_uid != real_uid) && !(real_uid == 0))
	    || atverify)
	    continue;

	if (sscanf(dirent->d_name, "%c%5lx%8lx", &queue, &jobno, &ctm) != 3)
	    continue;

	if (atqueue && (queue != atqueue))
	    continue;

	runtimer = 60 * (time_t) ctm;
	runtime = localtime(&runtimer);

	if (getenv("POSIXLY_CORRECT") != NULL) {
	    strftime(timestr, TIMESIZE, TIMEFORMAT_POSIX, runtime);
	} else {
	    strftime(timestr, TIMESIZE, TIMEFORMAT_ISO, runtime);
	}
	printf("%ld\t%s %c\n", jobno, timestr, queue);
    }
    PRIV_END
}

static void
process_jobs(int argc, char **argv, int what)
{
    /* Delete every argument (job - ID) given
     */
    int i;
    struct stat buf;
    DIR *spool;
    struct dirent *dirent;
    unsigned long ctm;
    char queue;
    long jobno;

    PRIV_START

    if (chdir(ATJOB_DIR) != 0)
	perr("Cannot change to " ATJOB_DIR);

    if ((spool = opendir(".")) == NULL)
	perr("Cannot open " ATJOB_DIR);

    PRIV_END

    /*  Loop over every file in the directory 
     */
	while ((dirent = readdir(spool)) != NULL) {

	PRIV_START
	if (stat(dirent->d_name, &buf) != 0)
	    perr("Cannot stat in " ATJOB_DIR);
	PRIV_END

	    if (sscanf(dirent->d_name, "%c%5lx%8lx", &queue, &jobno, &ctm) != 3)
	    continue;

	for (i = optind; i < argc; i++) {
	    if (atoi(argv[i]) == jobno) {
		if ((buf.st_uid != real_uid) && !(real_uid == 0)) {
		    fprintf(stderr, "%s: Not owner\n", argv[i]);
		    exit(EXIT_FAILURE);
		}
		switch (what) {
		case ATRM:

		    PRIV_START

			if (queue == '=') {
			    fprintf(stderr, "Warning: deleting running job\n");
			}
			if (unlink(dirent->d_name) != 0)
			    perr("Cannot unlink %.500s", dirent->d_name);

		    PRIV_END

		    break;

		case CAT:
		    {
			FILE *fp;
			int ch;

			PRIV_START

			    fp = fopen(dirent->d_name, "r");

			PRIV_END

			if (!fp) {
			    perr("Cannot open %s", dirent->d_name);
			}
			while ((ch = getc(fp)) != EOF) {
			    putchar(ch);
			}
		    }
		    break;

		default:
		    fprintf(stderr,
			    "Internal error, process_jobs = %d\n", what);
		    exit(EXIT_FAILURE);
		    break;
		}
	    }
	}
    }
}				/* delete_jobs */

/* Global functions */

void *
mymalloc(size_t n)
{
    void *p;
    if ((p = malloc(n)) == (void *) 0) {
	fprintf(stderr, "Virtual memory exhausted\n");
	exit(EXIT_FAILURE);
    }
    return p;
}

int
main(int argc, char **argv)
{
    int c;
    char queue = DEFAULT_AT_QUEUE;
    char queue_set = 0;
    char *pgm;

    int program = AT;		/* our default program */
    char *options = "q:f:mvldVc";	/* default options for at */
    int disp_version = 0;
    time_t timer;
    struct passwd *pwe;
    struct group *ge;

    RELINQUISH_PRIVS

    if ((pwe = getpwnam(DAEMON_USERNAME)) == NULL)
	perr("Cannot get uid for " DAEMON_USERNAME);

    daemon_uid = pwe->pw_uid;

    if ((ge = getgrnam(DAEMON_GROUPNAME)) == NULL)
	perr("Cannot get gid for " DAEMON_GROUPNAME);

    daemon_gid = ge->gr_gid;

    /* Eat any leading paths
     */
    if ((pgm = strrchr(argv[0], '/')) == NULL)
	pgm = argv[0];
    else
	pgm++;

    namep = pgm;

    /* find out what this program is supposed to do
     */
    if (strcmp(pgm, "atq") == 0) {
	program = ATQ;
	options = "q:vV";
    } else if (strcmp(pgm, "atrm") == 0) {
	program = ATRM;
	options = "V";
    }
    /* process whatever options we can process
     */
    opterr = 1;
    while ((c = getopt(argc, argv, options)) != EOF)
	switch (c) {
	case 'v':		/* verify time settings */
	    atverify = 1;
	    break;

	case 'm':		/* send mail when job is complete */
	    send_mail = 1;
	    break;

	case 'f':
	    atinput = optarg;
	    break;

	case 'q':		/* specify queue */
	    if (strlen(optarg) > 1)
		usage();

	    atqueue = queue = *optarg;
	    if (!(islower(queue) || isupper(queue)))
		usage();

	    queue_set = 1;
	    break;

	case 'd':
	    if (program != AT)
		usage();

	    program = ATRM;
	    options = "V";
	    break;

	case 'l':
	    if (program != AT)
		usage();

	    program = ATQ;
	    options = "q:vV";
	    break;

	case 'b':
	    if (program != AT)
		usage();

	    program = BATCH;
	    options = "f:q:mvV";
	    break;

	case 'V':
	    disp_version = 1;
	    break;

	case 'c':
	    program = CAT;
	    options = "";
	    break;

	default:
	    usage();
	    break;
	}
    /* end of options eating
     */

    if (disp_version)
	fprintf(stderr, "at version " VERSION "\n"
	   "Bug reports to: ig25@rz.uni-karlsruhe.de (Thomas Koenig)\n");

    /* select our program
     */
    if (!check_permission()) {
	fprintf(stderr, "You do not have permission to use %s.\n", namep);
	exit(EXIT_FAILURE);
    }
    switch (program) {
    case ATQ:

	REDUCE_PRIV(daemon_uid, daemon_gid)
	    list_jobs();
	break;

    case ATRM:

	REDUCE_PRIV(daemon_uid, daemon_gid)
	    process_jobs(argc, argv, ATRM);
	break;

    case CAT:

	process_jobs(argc, argv, CAT);
	break;

    case AT:
	if (argc > optind) {
	    timer = parsetime(argc - optind, argv + optind);
	} else {
	    timer = 0;
	}

	if (timer == 0) {
	    fprintf(stderr, "Garbled time\n");
	    exit(EXIT_FAILURE);
	}
	if (atverify) {
	    struct tm *tm = localtime(&timer);
	    fprintf(stderr, "%s\n", asctime(tm));
	}
	writefile(timer, queue);
	break;

    case BATCH:
	if (queue_set)
	    queue = toupper(queue);
	else
	    queue = DEFAULT_BATCH_QUEUE;

	if (argc > optind)
	    timer = parsetime(argc, argv);
	else
	    timer = time(NULL);

	if (atverify) {
	    struct tm *tm = localtime(&timer);
	    fprintf(stderr, "%s\n", asctime(tm));
	}
	writefile(timer, queue);
	break;

    default:
	panic("Internal error");
	break;
    }
    exit(EXIT_SUCCESS);
}
