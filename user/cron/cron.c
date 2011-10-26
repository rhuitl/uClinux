/*
 * cron.c -- Cron daemon
 *
 * (C) Copyright 2001, Lineo Inc. (www.lineo.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include "bitstring.h"

/* This defines the full path to the crontab file we'll be using.
 */
#ifndef CRONFILE
#define CRONFILE	"/etc/config/crontab"
#endif

/* This define the maximum clock delta we'll accept as legitimate.
 * Any time jump forwards or backwards in excess of this many seconds
 * causes our timing to reset and scheduled jobs in the interium to be
 * missed.
 */
#define TJMP	(60*60*3)


/* This one doesn't seem to be in the headers.
 */
extern char *itoa(int);
#if !defined(__UC_LIBC__)
char *itoa(int n)
{
	static char buf[32];
	sprintf(buf, "%d", n);
	return(buf);
}
#endif

extern int cron_parent_main(int, char **);

/* This structure contains all the necessary information about one job.
 * We maintain a singly linked list of these records and scan that to
 * determine if jobs should run or not.
 */
typedef struct cent_s {
	struct cent_s	 *next;			/* Link to next record */
	char		 *username;		/* Who should run this */
	char		 *prog;			/* Program to run (command line) */
	char		**environ;		/* Environment to run it in */
	uid_t		  user;			/* UID to run with */
	bitstr_t	  bit_decl(minutes, 60);/* Minutes to run at 0..59 */
	bitstr_t	  bit_decl(hours, 24);	/* Hours to run at 0..23 */
	bitstr_t	  bit_decl(dom, 32);	/* Day in month to run at 1..31 */
	bitstr_t	  bit_decl(months, 13);	/* Months to run at 1..12 */
	bitstr_t	  bit_decl(dow, 7);	/* Day of week to run at 0..6 */
} *centry;

static centry tasklist = NULL;


/* The record used to hold the basic environment structure.
 * This structure is used to build up the environment during crontab
 * read.  The cron jobs actually get given a single block of memory which
 * contains their environment which is built from this list.
 */
struct env_s {
	struct env_s	*next;			/* Link to next record */
	char		*name;			/* Name of variable */
	char		*value;			/* Value of variable */
} *env = NULL;


/* We duplicate the entire environment structure into a single block of memory.
 * We do this per cron job so that each can have its own environment if desired.
 */
static inline char **cloneenv(void) {
	struct env_s	 *p;
	int		  n = 1;
	int		  i, j;
	int		  sz = 0;
	char		**procenv;
	char		 *x;
	
	/* Figure out how many we've got */
	for (p=env; p!=NULL; n++,p=p->next)
		sz += strlen(p->name) + strlen(p->value) + 2;
	procenv = malloc(sizeof(char *)*n + sizeof(char) * sz);
	x = (char *)(procenv + n);
	procenv[n-1] = NULL;
	
	/* Copy the environemnt stuff across */
	for (i=0, p=env; p!=NULL; p=p->next, i++) {
		procenv[i] = x;
		for (j=0; p->name[j] != '\0'; j++)
			*x++ = p->name[j];
		*x++ = '=';
		for (j=0; p->value[j] != '\0'; j++)
			*x++ = p->value[j];
		*x++ = '\0';
	}
	return procenv;
}


/* Store a value into an environment record.  This will replace an old variable of the same name */
static inline void stoenv(const char *name, const char *val) {
	struct env_s *p;
	
	for (p=env; p!=NULL; p=p->next)
		if (strcmp(p->name, name) == 0)
			break;
	if (p == NULL) {
		p = calloc(1, sizeof(struct env_s));
		p->name = strdup(name);
		p->next = env;
		env = p;
	} else
		free(p->value);
	p->value = strdup(val);
}


/* Clear a specified environment variable.  This frees the associated record as well */
static inline void clrenv(const char *name) {
	struct env_s *p, *q=NULL;

	for (p=env; p!=NULL; q=p,p=p->next)
		if (strcmp(p->name, name) == 0) {
			if (q == NULL)
				env = p->next;
			else
				q->next = p->next;
			free(p->name);
			free(p->value);
			free(p);
			return;
		}
}


/* Totally destroy the cached environment */
static void zapenv(void) {
	struct env_s *p, *q;

	for (p=env; p!=NULL; p=q) {
		q = p->next;
		free(p->name);
		free(p->value);
		free(p);
	}
	env = NULL;
}


/* Locate the string in the array of three character strings
 */
static int loc_string(char **s, const char *const abbrs[]) {
	int i;
	
	for (i=0; abbrs[i] != NULL; i++)
		if (strncasecmp(*s, abbrs[i], 3) == 0) {
			*s += 3;
			return i;
		}
	return -1;
}


/* Given a string of comma separated values of the form:
 *	n
 *	n-m
 *	n-m/s
 * build a representative bit string for the specified values.
 */
static int decode_elem(char *str, int nbits, const char *const abbrs[], bitstr_t *bits, int zerov) {
	char *p;
	int   sval, eval, step;
	int   i;
	int   base;

	if (str == NULL)
		return 0;
	if (zerov < 0)
		base = 1;
	else
		base = 0;
	bit_nclear(bits, base, nbits-1);
	for (;str != NULL && *str != '\0'; str=p) {
		/* See if we're comma separated and if so grab the first */
		p = strchr(str, ',');
		if (p != NULL)
			*p++ = '\0';
		step = 1;
		if (*str == '*') {		/* Special case: from start to end */
			sval = base;
			eval = nbits-1;
			str++;
		} else {
			/* Find the initial value */
			if (isdigit(*str))	sval = strtol(str, &str, 10);
			else if (abbrs != NULL)	sval = loc_string(&str, abbrs);
			else return 0;
			if (sval == zerov) sval = 0;
			if (sval < base || sval >= nbits)
				return 0;
			eval = sval;
			/* Check for a range */
			if (*str == '-') {
				str++;
				if (isdigit(*str))	eval = strtol(str, &str, 10);
				else if (abbrs != NULL)	eval = loc_string(&str, abbrs);
				else return 0;
				if (eval == zerov) eval = 0;
				if (eval < base || eval >= nbits)
					return 0;
				if (eval < sval) {
					i = sval;
					sval = eval;
					eval = i;
				}
			}
		}
		/* Do we have an increment here? */
		if (*str == '/') {
			str++;
			if (!isdigit(*str))
				return 0;
			step = atoi(str);
			if (step <= 0 || step > (eval - sval))
				return 0;
		}
		/* Set the corresponding bits */
		for (i=sval; i<=eval; i += step)
			bit_set(bits, i);
	}
	return 1;
}


/* This routine breaks a line into pieces and fills in each of the structures fields.
 */
static inline int decode_line(char *line) {
	centry		 pent;		/* Allocated struct to link into list */
	char		*p;
	struct passwd	*pwd;
	static const char *const month_names[] =
			{ "xxx", "jan", "feb", "mar", "apr", "may", "jun",
			  "jul", "aug", "sep", "oct", "nov", "dec", NULL };
	static const char *const day_names[] =
			{ "sun", "mon", "tue", "wed", "thu", "fri", "sat" , NULL };

	/* Allocate space for the new structure in the list */
	pent = calloc(1, sizeof(struct cent_s));
	if (pent == NULL)
		goto failed;

	/* Decode the time fields.  This isn't too bad but we've got a problem in that
	 * some things are allowed to start from zero and others from one.
	 */
	if (!decode_elem(strtok(line, " \t"), 60, NULL, pent->minutes, 0))
		goto failed;
	if (!decode_elem(strtok(NULL, " \t"), 24, NULL, pent->hours, 0))
		goto failed;
	if (!decode_elem(strtok(NULL, " \t"), 32, NULL, pent->dom, -1))
		goto failed;
	if (!decode_elem(strtok(NULL, " \t"), 13, month_names, pent->months, -1))
		goto failed;
	if (!decode_elem(strtok(NULL, " \t"), 7, day_names, pent->dow, 7))
		goto failed;
	/* Get user name */
	p = strtok(NULL, " \t");
	if (p == NULL)
		goto failed;
	if (isdigit(*p)) {
		pent->user = atoi(p);
		pwd = getpwuid(pent->user);
		if (pwd == NULL) {
			char *r, *q = itoa(pent->user);
			r = (char *)malloc(strlen(q) + 5);
			strcpy(r, "user");
			strcpy(r+4, q);
			pent->username = r;
		} else
			pent->username = strdup(pwd->pw_name);
	} else {
		pwd = getpwnam(p);
		if (pwd == NULL)
			return 0;
		pent->username = strdup(pwd->pw_name);
		if (pent->username == NULL)
			return 0;
		pent->user = pwd->pw_uid;
	}
	/* Decode program name and args */
	p = strtok(NULL, "");
	if (p == NULL)
		goto failed;
	pent->prog = strdup(p);
	if (pent->prog == NULL)
		goto failed;
	/* Clone the environment as it is now */
	pent->environ = cloneenv();
	if (pent->environ == NULL)
		goto failed;
	/* Link structure into the list */
	pent->next = tasklist;
	tasklist = pent;
	return 1;

failed:
	if (pent != NULL) {
		if (pent->username != NULL) free(pent->username);
		if (pent->environ != NULL) free(pent->environ);
		if (pent->prog != NULL) free(pent->prog);
		free(pent);
	}
	return 0;
}


/* Decode an environemnt variable line.
 * Only two cases to worry about.  NAME=VALUE and NAME=
 * The second of these unsets the variable.
 */
static inline int decode_env(char *p) {
	char *q, *r;
	
	q = strchr(p, '=');
	if (q == NULL)
		return 0;
	for (r=q-1; isspace(*r) && r != p; *r-- = '\0');
	if (*p == '\0')
		return 0;
	*q++ = '\0';
	while (*q != '\0' && isspace(*q)) q++;
	if (*q == '\0') {		/* Clear variable */
		clrenv(p);
	} else {			/* Set variable */
		stoenv(p, q);
	}
	return 1;
}


/* This function operates kind of like fgets() except we read from a
 * file descriptor not a FILE *.  Efficiency really isn't that
 * important here since config file reads aren't all that common
 * thus we'll read the file in char at a time.
 */
static inline int fdgets(char *s, int count, int f) {
	int	 i;
	char	 ch;

	for (i = count-1; i>0; i--) {
		if (read(f, &ch, sizeof(char)) <= 0) {
			if (i > 1)
				*s++ = '\n';
			*s = '\0';
			return 0;
		}
		*s++ = (char)ch;
		if (ch == '\n')
			break;
	}
	*s = '\0';
	return 1;
}


/* Load the configuration file if necessary.
 * Return non-zero if we've successifully read the file or if the
 * file hasn't changed.
 */
static inline int load_file(const char *fname)
{
	int		 fp;
	struct stat	 lst, fst;
	char		 buf[BUFSIZ];
	centry		 task, next_task;
	char		*p;
	int		 line = 0;
	int		 res;
	int		 moreinput;
	static time_t	 file_mtime = 0;

	/* Stage one is open the file for read */
	fp = open(fname, O_RDONLY);
	if (fp == -1) {
		syslog(LOG_ERR, "cannot open crontab");
		goto failed;
	}
	
	/* Stage two is check permissions on file */
	if (0 != lstat(fname, &lst) || 0 != fstat(fp, &fst)) {
		syslog(LOG_ERR, "cannot stat crontab");
		goto failed;
	}
	if ((lst.st_mode & S_IFREG) == 0) {
		syslog(LOG_ERR, "crontab not regular file");
		goto failed;
	}
	if (fst.st_ino != lst.st_ino) {
		syslog(LOG_ERR, "crontab inode changed between stat and open");
		goto failed;
	}
	if (fst.st_dev != lst.st_dev) {
		syslog(LOG_ERR, "crontab device changed between stat and open");
		goto failed;
	}
	if (fst.st_uid) {
		syslog(LOG_ERR, "crontab not owned by uid 0");
		goto failed;
	}
	if (fst.st_mode & (S_IWGRP | S_IWOTH)) {
		syslog(LOG_ERR, "crontab group and/or world writable");
		goto failed;
	}

	/* Check to see if the file has been modified */
	if (fst.st_mtime == file_mtime)
		goto success;
	file_mtime = fst.st_mtime;
	syslog(LOG_INFO, "loading crontab file %s", fname);

	/* Purge any existing tasks from the task list */
	for (task = tasklist; task != NULL; task=next_task) {
		next_task = task->next;
		if (task->username != NULL)
			free(task->username);
		if (task->prog != NULL)
			free(task->prog);
		if (task->environ != NULL)
			free(task->environ);
		free(task);
	}
	tasklist = NULL;
	
	/* Purge any saved environment and restore to default */
	zapenv();
	stoenv("SHELL", "/bin/sh");
	stoenv("PATH", "/bin:/usr/bin:/etc");

	/* Finally get around to reading the file */
	do {
		moreinput = fdgets(buf, BUFSIZ, fp);
		line++;
		/* Remove trailing newline and spaces if present */
		if ((p = strchr(buf, '\n')) == NULL)
			goto failed;
		while (isspace(*p))
			*p-- = '\0';

		/* Remove leading spaces */
		for (p = buf; *p != '\0' && isspace(*p); p++);
		if (*p == '\0') continue;
		if (*p == '#') continue;

		/* Now decode everything */
		if (isdigit(*p) || *p == '*') {		/* Assume this is a command */
			res = decode_line(p);
		} else {			/* This will be an environment variable setting */
			res = decode_env(p);
		}
		if (!res) {
			syslog(LOG_ERR, "crontab has malformed input line %d", line);
		}
	} while (moreinput);
	zapenv();		/* Do it again to save memory */
success:
	close(fp);
	return 1;
/* Come here on failure for any reason */
failed:
	if (fp >= 0)
		close(fp);
	return 0;
}


/* This routine runs along the task list and executes any job that wants
 * to be run.
 */
static void check_runs(struct tm *now)
{
	centry	 task;
	int	 pid;
	char    *av[5];
	char     s[26];
	char	*q;

	if (tasklist == NULL)
		return;
	for (task = tasklist; task != NULL; task = task->next) {
		if (bit_test(task->minutes, now->tm_min) &&
		    bit_test(task->hours, now->tm_hour) &&
		    bit_test(task->months, now->tm_mon+1) &&
		    bit_test(task->dom, now->tm_mday) &&
		    bit_test(task->dow, now->tm_wday)) {
			asctime_r(now, s);
			q = strchr(s, '\n');
			if (q != NULL)
				*q = '\0';
			syslog(LOG_INFO, "running %s", task->prog);
			av[0] = "cron-parent";		/* Build the cron-parent's argv structure */
			av[1] = task->prog;
			av[2] = itoa(task->user);
			av[3] = task->username;
			av[4] = NULL;

			pid = vfork();
			if (pid == 0) {	/* Child */
				/* This job is ready to run.  Exec the special cron parent
				 * process which actually runs the job.
				 */
				execve("/bin/cron", av, task->environ);
				syslog(LOG_CRIT, "unable to exec task cron-parent");
				_exit(0);
			}
			if (pid < 0)
				syslog(LOG_ERR, "unable to exec task %s", task->prog);
		}
	}
}


/* The main driving routine */
int main(int argc, char *argv[])
{
	time_t		 t;		/* Current time */
	time_t		 target;	/* Next wake up time */
	struct tm	*now;		/* Pointer to current expanded time */
	int		 delay;		/* How long to sleep for */

	if (strcmp(argv[0], "cron-parent") == 0) {
		return cron_parent_main(argc, argv);
	}

	openlog("cron", LOG_PID, LOG_CRON);
	signal(SIGCHLD, SIG_IGN);

tjmp:	target = time(NULL);
	now = localtime(&target);
	target += 60 - now->tm_sec;

	for (;;) {
		delay = target - time(NULL);
		if (delay < -TJMP || delay > TJMP) goto tjmp;
		while (delay > 0)
			delay = sleep(delay);

		now = localtime(&target);
		target += 60;		/* Next awakening */

		load_file(CRONFILE);	/* Load the crontab if necessary */
		check_runs(now);	/* Run anything that needs to be run */
	}
}
