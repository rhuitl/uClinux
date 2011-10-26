/*
 * cron-parent.c -- Parent process run by cron
 *
 * (C) Copyright 2001, Lineo Inc. (www.lineo.com)
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#if 0
/* Defining this symbol turns off the closing of *all* FDs prior to execution.
 * Stderr will be cloned to the FD mentioned in this #define and that FD will
 * not be closed.  This allows for debug print statement etc after the
 * closing of FDs has occured.
 */
#define ERRFD	25
#else
#undef ERRFD
#endif

/* Provide some symbolic names for the FDs the parent will use.
 * The child uses 0, 1 & 2 as per usual.
 */
#define PLISTENFD	8
#define PSENDFD		9

static char **av;
static char *path;
static char *stdinstr;			/* Jobs standard input string */
static const char *mailuser;		/* Who to notify with job output */
static const char *mailhost;		/* Where to send the mail */
static const char *hname = NULL;	/* Override host name */
static const char *outfile = NULL;	/* Output file name */
extern char **environ;

#ifdef ERRFD
FILE *errf;
#define print(format, args...)	fprintf(errf, format "\n", ## args); fflush(errf)
#else
#define print(format, args...)	syslog(LOG_ERR, format, ## args);
#endif

/* Process the command line and build everything we need up */
static inline void parseargs(char *args)
{
	char *p, *q, *r;
	int len, i;
	struct stat buf;
	/* First up mangle out % characters */
	for (p = q = args; *q != '\0'; q++) {
		if (*q == '%') {
			if (q[1] == '%')
				*p++ = *q++;
			else
				*p++ = '\n';
		} else
			*p++ = *q;
	}
	p = strchr(args, '\n');
	if (p != NULL) {
		*p++ = '\0';		/* Terminate the command line */
		stdinstr = p;		/* Set stdin to the rest of the buffer */
	} else
		stdinstr = NULL;
	
	/* Now go through the command line and build the args up */
	p = strtok(args, " \t");
	if (p == NULL) exit(1);
	av[0] = strdup(p);
	for(i=1; i < 100 && (p = strtok(NULL, " \t")) != NULL;) {
		if (*p == '>') {
			/* Check for multiple output files */
			if (outfile != NULL) {
				print("Multiple output redirections encountered");
				exit(1);
			}
			outfile = p+1;
			if (*outfile == '\0') {
				outfile = strtok(NULL, " \t");
				if (outfile == NULL) {
					print("No output file specified");
					exit(1);
				}
			}
		} else
			av[i++] = strdup(p);
	}
	av[i] = NULL;

	/* Now figure out the full path to the executable */
	path = NULL;
	if (av[0][0] == '/') path = av[0];
	else {
		p = getenv("PATH");
		len = strlen(p);
		q = malloc(len + strlen(av[0]) +  2);
		
		r = strtok(p, ":");
		if (r == NULL) exit(1);
		do {
			strcpy(q, r);
			len = strlen(q);
			q[len] = '/';
			strcpy(q+len+1, av[0]);
			if (stat(q, &buf) == -1)
				continue;
			if (buf.st_uid == getuid()) {
				if (buf.st_mode & S_IXUSR) {
					path = q;
					break;
				}
			} else if (buf.st_gid == getgid()) {
				if (buf.st_mode & S_IXGRP) {
					path = q;
					break;
				}
			} else {
				if (buf.st_mode & S_IXOTH) {
					path = q;
					break;
				}
			}
		} while ((r = strtok(NULL, ":")) != NULL);
		free(q);
	}
	if (path == NULL) {
		print("Cannot locate executable: %s", av[0]);
		exit(1);		/* Cannot locate it */
	}
}


/* Switch our user ID and groups over
 */
static inline void changeuser(int uid, const char *user)
{
	initgroups(user, uid);
	setgid(uid);
	setuid(uid);
	mailuser = user;
}

/* Set any required environemnt variables and extract necessary
 * information from the environment
 */
static inline void setenviron(void)
{
	char *s;
	if (getenv("PATH") == NULL)
		putenv("PATH=/bin:/usr/bin:/etc");
	/* Figure out who should get email notification */
	s = getenv("MAILTO");
	if (s != NULL) {
		if (strcmp(s, "nobody") == 0)
			mailuser = NULL;
		else
			mailuser = s;
	}
	mailhost = getenv("MAILHOST");
	/* Allow override host name */
	s = getenv("HOSTNAME");
	if (s != NULL)
		hname = s;
	/* Set home directory */
	s = getenv("HOME");
	if (s == NULL) s = "/tmp";
	chdir(s);
}

/* Set up the jobs file descriptors
 * This means closing everything and then setting up a pair of pipes
 * to allow proper communication with the child.  The final configuration
 * is:
 *
 * 0  stdin for child
 * 1  stdout for child
 * 2  stderr for child == 1
 * 8  stdout/stderr destination for parent
 * 9  stdin source for parent
 */
static inline void setupfds(void)
{
	int i;
	int outdes[2];
	int indes[2];
	struct rlimit rlim;

	/* Close all fds */
	getrlimit(RLIMIT_NOFILE, &rlim);
	for (i=0; i<rlim.rlim_cur; i++)
#ifdef ERRFD
		if (i != ERRFD)
#endif
		close(i);
	/* Now create a pair of pipes to allow communication between the master
	 * and the child.
	 */
	if (mailuser == NULL || mailhost == NULL) {
		if (outfile != NULL) {
			unlink(outfile);
			i = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		}
		if (outfile == NULL || i == -1)
			i = open("/dev/null", O_WRONLY);
		dup2(i, 1);			/* FD 1 : clne to stdout */
		dup2(i, 2);			/* FD 2 : clone to stderr */
		close (i);			/* FD 0 : finished with this */
	} else {
		pipe(outdes);			/* FD 0 & 1 */
		dup2(outdes[1], 2);		/* FD 2 : stderr for child */
		dup2(outdes[0], PLISTENFD);	/* FD 8 : parent to listen stderr/stdin */
		close(outdes[0]);		/* FD 0 : moved this already */
	}
	if (stdinstr != NULL) {
		pipe(indes);			/* FD 0 & 3 */
		dup2(indes[1], PSENDFD);	/* FD 9 : parent to talk on stdin */
		close(indes[1]);		/* FD 3 */
	} else {
		open("/dev/null", O_RDONLY);	/* FD 0 : stdin */
	}
}


/* Arrange for the stdout stream from the child process to be pumped into
 * the stdin stream for a mail process
 */
static inline int handlestdout(void)
{
	pid_t pid;
	int   i = 0;
	char *s;

	if (mailuser == NULL || mailhost == NULL)
		return 0;

	/* Okay to overwrite av[] array now because our child has already started and got
	 * its own copy of this stuff.
	 */
	av[i++] = "cron-mail";			/* Name of process */
	av[i++] = "-s";				/* Provide a subject line */
#define SUBJECT "Output from: "
	s = malloc(strlen(path) + sizeof(SUBJECT));
	strcpy(s, SUBJECT);		/* Build a useful subject */
	strcpy(s + sizeof(SUBJECT)-1, path);
#undef SUBJECT
	av[i++] = s;
	if (hname != NULL) {
		av[i++] = "-H";			/* Override host name */
		av[i++] = (char *)hname;
	}
	av[i++] = "-L";				/* Use syslog for errors */
	av[i++] = "-S";				/* Send to this host */
	av[i++] = (char *)mailhost;
	av[i++] = (char *)mailuser;		/* Who to send to */
	av[i++] = NULL;

	pid = vfork();
	if (pid < 0) exit(1);
	if (pid == 0) {
		dup2(PLISTENFD, 0);
		close(PLISTENFD);
		close(PSENDFD);
		execve("/bin/mail", av, environ);
		_exit(1);
	}
	close(PLISTENFD);
	free(s);
	return pid;
}


/* Send the stdin string to our child process
 */
static inline void sendstdin(void)
{
	size_t	len;
	size_t	nbytes = 0;
	size_t	res;

	if (stdinstr == NULL) return;
	len = strlen(stdinstr);
	while (nbytes < len) {
		res = write(PSENDFD, stdinstr+nbytes, len-nbytes);
		if (res == -1) break;
		nbytes += res;
	}
	/* Make sure there is a final newline character */
	if (stdinstr[len-1] != '\n')
		write(PSENDFD, "\n", 1);
	close(PSENDFD);
}


int cron_parent_main(int argc, char *argv[])
{
	int pid, p2;
	extern int errno;

#ifdef ERRFD
	dup2(2, ERRFD);
	errf = fdopen(ERRFD, "w");
#endif
	if (argc != 4) exit(1);			/* Enough args? */
	av = malloc(sizeof(char *) * 101);	/* Allocate an argv array */
	if (av == NULL) {
		print("Malloc failed: errno = %d", errno);
		_exit(1);
	}
	setsid();				/* Create our own little group */
	changeuser(atoi(argv[2]), argv[3]);	/* Give up privs */
	setenviron();				/* Sanitise environ and extract useful information */
	
	parseargs(argv[1]);			/* Process the jobs command line */
	setupfds();				/* Set up file descriptors */

	pid = vfork();				/* Create the child process */
	if (pid == 0) {
		close(PLISTENFD);		/* Close parent only FDs */
		close(PSENDFD);
		execve(path, av, environ);	/* Run the job */
		print("Exec failed: errno = %d", errno);
		_exit(1);
	}
	if (pid < 0) exit(1);
	/* Parent processing */
	close(0);
	close(1);
	close(2);
	p2 = handlestdout();			/* Pass stdout to mail */
	sendstdin();				/* Send stdin to process if required */
	waitpid(pid, NULL, 0);			/* Wait for children to exit */
	if (p2 != 0)
		waitpid(p2, NULL, 0);
	return 0;
}
