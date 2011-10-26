/*
 * Copyright (c) 1993 by David I. Bell
 * Permission is granted to use, distribute, or modify this source,
 * provided that this copyright notice remains intact.
 *
 * Utility routines.
 */

#include "sash.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <utime.h>
#include <fcntl.h>
#include <fnmatch.h>

#ifdef L_intflag

int intflag;

#endif

#ifdef L_modestring

/*
 * Return the standard ls-like mode string from a file mode.
 * This is static and so is overwritten on each call.
 */
char *
modestring(mode)
{
	static	char	buf[12];

	strcpy(buf, "----------");

	/*
	 * Fill in the file type.
	 */
	if (S_ISDIR(mode))
		buf[0] = 'd';
	if (S_ISCHR(mode))
		buf[0] = 'c';
	if (S_ISBLK(mode))
		buf[0] = 'b';
	if (S_ISFIFO(mode))
		buf[0] = 'p';
#ifdef	S_ISLNK
	if (S_ISLNK(mode))
		buf[0] = 'l';
#endif
#ifdef	S_ISSOCK
	if (S_ISSOCK(mode))
		buf[0] = 's';
#endif

	/*
	 * Now fill in the normal file permissions.
	 */
	if (mode & S_IRUSR)
		buf[1] = 'r';
	if (mode & S_IWUSR)
		buf[2] = 'w';
	if (mode & S_IXUSR)
		buf[3] = 'x';
	if (mode & S_IRGRP)
		buf[4] = 'r';
	if (mode & S_IWGRP)
		buf[5] = 'w';
	if (mode & S_IXGRP)
		buf[6] = 'x';
	if (mode & S_IROTH)
		buf[7] = 'r';
	if (mode & S_IWOTH)
		buf[8] = 'w';
	if (mode & S_IXOTH)
		buf[9] = 'x';

	/*
	 * Finally fill in magic stuff like suid and sticky text.
	 */
	if (mode & S_ISUID)
		buf[3] = ((mode & S_IXUSR) ? 's' : 'S');
	if (mode & S_ISGID)
		buf[6] = ((mode & S_IXGRP) ? 's' : 'S');
	if (mode & S_ISVTX)
		buf[9] = ((mode & S_IXOTH) ? 't' : 'T');

	return buf;
}

#endif

#ifdef L_timestring

/*
 * Get the time to be used for a file.
 * This is down to the minute for new files, but only the date for old files.
 * The string is returned from a static buffer, and so is overwritten for
 * each call.
 */
char *
timestring(t)
	long	t;
{
	long		now;
	char		*str;
	static	char	buf[26];

	time(&now);

	str = ctime(&t);

	strcpy(buf, &str[4]);
	buf[12] = '\0';

	if ((t > now) || (t < now - 365*24*60*60L)) {
		strcpy(&buf[7], &str[20]);
		buf[11] = '\0';
	}

	return buf;
}

#endif

#ifdef L_isadir

/*
 * Return TRUE if a filename is a directory.
 * Nonexistant files return FALSE.
 */
BOOL
isadir(name)
	char	*name;
{
	struct	stat	statbuf;

	if (stat(name, &statbuf) < 0)
		return FALSE;

	return S_ISDIR(statbuf.st_mode);
}

#endif

#ifdef L_copyfile

/*
 * Copy one file to another, while possibly preserving its modes, times,
 * and modes.  Returns TRUE if successful, or FALSE on a failure with an
 * error message output.  (Failure is not indicted if the attributes cannot
 * be set.)
 */
BOOL
copyfile(srcname, destname, setmodes)
	char	*srcname;
	char	*destname;
	BOOL	setmodes;
{
	int		rfd;
	int		wfd;
	int		rcc;
	int		wcc;
	char		*bp;
	struct	stat	statbuf1;
	struct	stat	statbuf2;
	struct	utimbuf	times;
	int len = 8192-16;
	char * buf = 0;
	
	if (stat(srcname, &statbuf1) < 0) {
		perror(srcname);
		return FALSE;
	}

	if (stat(destname, &statbuf2) < 0) {
		statbuf2.st_ino = -1;
		statbuf2.st_dev = -1;
	}

	if (S_ISREG(statbuf1.st_mode) &&
			(statbuf1.st_dev == statbuf2.st_dev) &&
		(statbuf1.st_ino == statbuf2.st_ino))
	{
		fprintf(stderr, "Copying file \"%s\" to itself\n", srcname);
		return FALSE;
	}

	rfd = open(srcname, 0);
	if (rfd < 0) {
		perror(srcname);
		return FALSE;
	}

	wfd = open(destname, O_WRONLY|O_CREAT|O_TRUNC, statbuf1.st_mode);
	if (wfd < 0) {
		perror(destname);
		close(rfd);
		return FALSE;
	}

	buf = malloc(len);
	if (!buf) {
		fprintf(stderr,"Unable to allocate buffer of %d bytes\n", len);
		return FALSE;
	}
	
	while ((rcc = read(rfd, buf, len)) > 0) {
		if (intflag) {
			close(rfd);
			close(wfd);
			free(buf);
			return FALSE;
		}

		bp = buf;
		while (rcc > 0) {
			wcc = write(wfd, bp, rcc);
			if (wcc < 0) {
				perror(destname);
				free(buf);
				goto error_exit;
			}
			bp += wcc;
			rcc -= wcc;
		}
	}
	
	free(buf);

	if (rcc < 0) {
		perror(srcname);
		goto error_exit;
	}

	close(rfd);
	if (close(wfd) < 0) {
		perror(destname);
		return FALSE;
	}

	if (setmodes) {
		(void) chmod(destname, statbuf1.st_mode);

		(void) chown(destname, statbuf1.st_uid, statbuf1.st_gid);

		times.actime = statbuf1.st_atime;
		times.modtime = statbuf1.st_mtime;

		(void) utime(destname, &times);
	}

	return TRUE;


error_exit:
	close(rfd);
	close(wfd);

	return FALSE;
}

#endif

#ifdef L_buildname

/*
 * Build a path name from the specified directory name and file name.
 * If the directory name is NULL, then the original filename is returned.
 * The built path is in a static area, and is overwritten for each call.
 */
char *
buildname(dirname, filename)
	char	*dirname;
	char	*filename;
{
	char		*cp;
	static	char	buf[PATHLEN];

	if ((dirname == NULL) || (*dirname == '\0'))
		return filename;

	cp = strrchr(filename, '/');
	if (cp)
		filename = cp + 1;

	strcpy(buf, dirname);
	strcat(buf, "/");
	strcat(buf, filename);

	return buf;
}

#endif

#ifdef L_expandwildcards

/*
 * Expand the wildcards in a filename, if any.
 * Returns an argument list with matching filenames in sorted order.
 * The expanded names are stored in memory chunks which can later all
 * be freed at once.  Returns zero if the name is not a wildcard, or
 * returns the count of matched files if the name is a wildcard and
 * there was at least one match, or returns -1 if too many filenames
 * matched (with an error output).
 * If the name is a wildcard and no names match, returns 0 as
 * if the name were not a wildcard.
 */
int
expandwildcards(name, maxargc, retargv)
	char	*name;
	int	maxargc;
	char	*retargv[];
{
	char	*last;
	char	*cp1, *cp2, *cp3;
	DIR	*dirp;
	struct	dirent	*dp;
	int	dirlen;
	int	matches;
	char	dirname[PATHLEN];

	last = strrchr(name, '/');
	if (last)
		last++;
	else
		last = name;

	cp1 = strchr(name, '*');
	cp2 = strchr(name, '?');
	cp3 = strchr(name, '[');

	if ((cp1 == NULL) && (cp2 == NULL) && (cp3 == NULL))
		return 0;

	if ((cp1 && (cp1 < last)) || (cp2 && (cp2 < last)) ||
		(cp3 && (cp3 < last)))
	{
		fprintf(stderr, "Wildcards only implemented for last filename component\n");
		return -1;
	}

	dirname[0] = '.';
	dirname[1] = '\0';

	if (last != name) {
		memcpy(dirname, name, last - name);
		dirname[last - name - 1] = '\0';
		if (dirname[0] == '\0') {
			dirname[0] = '/';
			dirname[1] = '\0';
		}
	}

	dirp = opendir(dirname);
	if (dirp == NULL) {
		perror(dirname);
		return -1;
	}

	dirlen = strlen(dirname);
	if (last == name) {
		dirlen = 0;
		dirname[0] = '\0';
	} else if (dirname[dirlen - 1] != '/') {
		dirname[dirlen++] = '/';
		dirname[dirlen] = '\0';
	}

	matches = 0;

	while ((dp = readdir(dirp)) != NULL) {
		if ((strcmp(dp->d_name, ".") == 0) ||
			(strcmp(dp->d_name, "..") == 0))
				continue;

		if (!match(dp->d_name, last))
			continue;

		if (matches >= maxargc) {
			fprintf(stderr, "Too many filename matches\n");
			closedir(dirp);
			return -1;
		}

		cp1 = getchunk(dirlen + strlen(dp->d_name) + 1);
		if (cp1 == NULL) {
			fprintf(stderr, "No memory for filename\n");
			closedir(dirp);
			return -1;
		}

		if (dirlen)
			memcpy(cp1, dirname, dirlen);
		strcpy(cp1 + dirlen, dp->d_name);

		retargv[matches++] = cp1;
	}

	closedir(dirp);

	if (matches == 0) {
		return 0;
	}

	qsort((char *) retargv, matches, sizeof(char *), namesort);

	return matches;
}

#endif

#ifdef L_namesort

/*
 * Sort routine for list of filenames.
 */
int
namesort(p1, p2)
	char	**p1;
	char	**p2;
{
	return strcmp(*p1, *p2);
}

#endif

#ifdef L_match

/*
 * Routine to see if a text string is matched by a wildcard pattern.
 * Returns TRUE if the text is matched, or FALSE if it is not matched
 * or if the pattern is invalid.
 *  *		matches zero or more characters
 *  ?		matches a single character
 *  [abc]	matches 'a', 'b' or 'c'
 *  \c		quotes character c
 *  Adapted from code written by Ingo Wilken.
 */
BOOL
match(text, pattern)
	char	*text;
	char	*pattern;
{
	return fnmatch(pattern, text, 0) == 0;
}
#endif

#ifdef L_makeargs

/*
 * Take a command string, and break it up into an argc, argv list.
 * The returned argument list and strings are in static memory, and so
 * are overwritten on each call.  The argument array is ended with an
 * extra NULL pointer for convenience.  Returns TRUE if successful,
 * or FALSE on an error with a message already output.
 *
 * Note that leading quotes are *not* removed at this point, but
 * trailing quotes are.
 */
BOOL
makeargs(cmd, argcptr, argvptr)
	char	*cmd;
	int	*argcptr;
	char	***argvptr;
{
	char		*cp;
	int		argc;
	static char	strings[CMDLEN+1];
	static char	*argtable[MAXARGS+1];
	static char	quoted[MAXARGS+1];

	/*
	 * Copy the command string and then break it apart
	 * into separate arguments.
	 */
	strcpy(strings, cmd);
	argc = 0;
	cp = strings;

	while (*cp) {
		if (argc >= MAXARGS) {
			fprintf(stderr, "Too many arguments\n");
			return FALSE;
		}

		quoted[argc] = 0;
		argtable[argc++] = cp;

		while (*cp && !isblank(*cp)) {
			if (*cp == '"' || *cp == '\'') {
				char *sp = cp++;

				while (*cp && *cp != *sp)
					cp++;

				if (*cp == *sp) {
					/* Chop off the trailing quote, but leave the leading quote
					 * so that later processing will know the argument is quoted
					 */
					*cp++ = 0;
				}
			} else
				cp++;
		}

		while (isblank(*cp))
 			*cp++ = '\0';
	}

	argtable[argc] = NULL;

	*argcptr = argc;
	*argvptr = argtable;

 	return TRUE;
}

#endif

#ifdef L_makestring

/*
 * Make a NULL-terminated string out of an argc, argv pair.
 * Returns TRUE if successful, or FALSE if the string is too long,
 * with an error message given.  This does not handle spaces within
 * arguments correctly.
 */
BOOL
makestring(argc, argv, buf, buflen)
	char	**argv;
	char	*buf;
{
	int	len;

	while (argc-- > 0) {
		len = strlen(*argv);
		if (len >= buflen) {
			fprintf(stderr, "Argument string too long\n");
			return FALSE;
		}

		strcpy(buf, *argv++);

		buf += len;
		buflen -= len;

		if (argc)
			*buf++ = ' ';
		buflen--; 
	}

	*buf = '\0';

	return TRUE;
}

#endif

#ifdef L_chunks

typedef	struct	chunk	CHUNK;
#define	CHUNKINITSIZE	4
struct	chunk	{
	CHUNK	*next;
	char	data[CHUNKINITSIZE];	/* actually of varying length */
};


static	CHUNK *	chunklist;


/*
 * Allocate a chunk of memory (like malloc).
 * The difference, though, is that the memory allocated is put on a
 * list of chunks which can be freed all at one time.  You CAN NOT free
 * an individual chunk.
 */
char *
getchunk(size)
{
	CHUNK	*chunk;

	if (size < CHUNKINITSIZE)
		size = CHUNKINITSIZE;

	chunk = (CHUNK *) malloc(size + sizeof(CHUNK) - CHUNKINITSIZE);
	if (chunk == NULL)
		return NULL;

	chunk->next = chunklist;
	chunklist = chunk;

	return chunk->data;
}


/*
 * Free all chunks of memory that had been allocated since the last
 * call to this routine.
 */
void
freechunks()
{
	CHUNK	*chunk;

	while (chunklist) {
		chunk = chunklist;
		chunklist = chunk->next;
		free((char *) chunk);
	}
}

#endif


#ifdef L_expandenvvar

/* Expand environment variables
 * Variable names must use a-z, A-Z, 0-9, or _
 * Backslashes are also interpreted to preserve the literal value of the
 * next character.
 * Returns NULL if there is an error, otherwise returns a pointer
 * to a static buffer containing the expand command line.
 *
 * Makes a lame attempt to not expand inside single quotes.
 */
char *
expandenvvar(cmd)
	char	*cmd;
{
	static char newcmd[CMDLEN+1];
	char* newp = newcmd;
	int freelength = CMDLEN;	/* Don't include final terminator */
	char varname[CMDLEN+1];
	char* varp;
	char* value;
	int valuelength;
	int quoted = 0;

	if (cmd == NULL) {
		return NULL;
	}

	if (strlen(cmd) > freelength) {
		fprintf(stderr, "Variable expansion too long\n");
		return NULL;
	}

	while (*cmd) {
		int copy = 1;

		switch (*cmd) {
		case '$':
			if (!quoted) {
				copy = 0;
				cmd++;
				varp = varname;
				while (isalnum(*cmd) || (*cmd == '_') || (*cmd == '?')) {
					*varp++ = *cmd++;
				}
				*varp = '\0';
				if ((*varname) && (value = getenv(varname))) {
					valuelength = strlen(value);
					if (valuelength > freelength) {
						fprintf(stderr, "Variable expansion too long\n");
						return NULL;
					}
					strncpy(newp, value, valuelength);
					newp += valuelength;
					freelength -= valuelength;
				}
			}
			break;

		case '\'':
			quoted = !quoted;
			break;

		case '\\':
			cmd++;
			break;
		}

		if (copy) {
			if (freelength < 1) {
				fprintf(stderr, "Variable expansion too long\n");
				return NULL;
			}
			*newp++ = *cmd++;
			freelength--;
		}
	}

	*newp = '\0';

	return newcmd;
}

#endif


/* END CODE */
