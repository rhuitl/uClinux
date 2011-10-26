#ifndef lint
static char rcsid[] = "$Id: config.parse.c,v 1.21 1994/07/21 01:03:26 gkim Exp $";
#endif

/*
 * config.parse.c
 *
 *	read in the preen.config file
 *
 * Gene Kim
 * Purdue University
 */

#include "../include/config.h"
#include <stdio.h>
#ifdef STDLIBH
#include <stdlib.h>
#include <unistd.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef DIRENT
# include <dirent.h>
#else
# ifndef XENIX
#  include <sys/dir.h>
# else		/* XENIX */
#  include <sys/ndir.h>
# endif		/* XENIX */
#endif	/* DIRENT */
#if (defined(SYSV) && (SYSV < 3))
# include <limits.h>
#endif	/* SVR2 */
#include <ctype.h>
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#include "../include/list.h"
#include "../include/tripwire.h"

#if defined(SYSV) && (SYSV < 4)
#ifndef HAVE_LSTAT
#  define lstat(x,y) stat(x,y)
#endif
#endif		/* SYSV */

#if !defined(major)
#define major(x)        (((unsigned)(x)>>16)&0xffff)
#endif
#if !defined(minor)
#define minor(x)        ((x)&0xffff)
#endif

/* prototypes */
char *mktemp();
static void configfile_descend();

#ifndef L_tmpnam
# define L_tmpnam (unsigned int) MAXPATHLEN
#endif

/* global */
/*		we keep track of all the entry headers */
static struct list *prune_list = (struct list *) NULL;

/*
 * configfile_read(struct list **pp_list, struct list **pp_entry_list)
 *
 *	open the configuration file, and pulls out the {file/dir,ignore-flag}
 *	pairs.
 *
 *	(**pp_list) is pointer the head of the file list, where all the
 *	files are added to.
 */

void
configfile_read(pp_list, pp_entry_list)
    struct list **pp_list;
    struct list **pp_entry_list;
{
    FILE 	*fpin, *fpout = (FILE *) NULL;
    char	filename[MAXPATHLEN+512];
    char	ignorestring[1024];
    char	s[MAXPATHLEN+1024];
    char	configfile[MAXPATHLEN+512];
    char	*tmpfilename;
    char	number[128];
    int		entrynum = 0;
    int		err;

    /* to make code semi-reentrant */
    list_reset(&prune_list);

    /* don't print banner if we're in print-preprocessor mode */
    if (!printpreprocess && !quietmode)
	fputs("### Phase 1:   Reading configuration file\n", stderr);

    /* generate temporary file name */
    if ((tmpfilename = (char *) malloc(L_tmpnam + MAXPATHLEN)) == NULL) {
	perror("configfile_read: malloc()");
	exit(1);
    };
    (void) strcpy(tmpfilename, TEMPFILE_TEMPLATE);

    if ((char *) mktemp(tmpfilename) == NULL) {
	perror("configfile_read: mktemp()");
	exit(1);
    }

    /* generate configuration file name */
    if (specified_configmode != SPECIFIED_FILE)
	sprintf(configfile, "%s/%s", config_path, config_file);
    else
	(void) strcpy(configfile, specified_configfile);

    /* open the files */
    /* were we given a specific fd to use? */
    if (specified_configmode) {
	char errstr[1024];

	/* we already checked to see that it's a valid fd */
	if (!(fpin = (FILE *) fdopen(specified_configfd, "r"))) {
	    sprintf(errstr, "tripwire: Couldn't open fd!  fdopen()");
	    perror(errstr);
	    exit(1);
	}
	rewind(fpin);
	if ((err = ftell(fpin)) != 0) {
	    die_with_err("configfile_read: ftell()", NULL);
	}
    }
    /* otherwise, it's just a normal file */
    else if ((fpin = fopen(configfile, "r")) == NULL) {
	char errstr[1024];
	sprintf(errstr, "tripwire: Couldn't open config file '%s'", configfile);
	perror(errstr);
	exit(1);
    }

    /* if we've already preprocessed the file, we can skip this */
    /*		uh, we used to only parse the tw.config file once.
     *		this causes problems during interactive updates.
     *		so, with v1.2, we're a little slower, so sue me.
     * -ghk
     */

    err = umask(077);  /* to protect the tempfile */

    if ((fpout = fopen(tmpfilename, "w+")) == NULL) {
	sprintf(s, "tripwire: Couldn't open config file '%s'", configfile);
	perror(s);
	exit(1);
    }
    (void) umask(err);  /* return it to its former state */

    /* The following unlink accomplishes two things:
     *  1) if the program terminates, we won't leave a temp
     *     file sitting around with potentially sensitive names
     *     in it.
     *  2) the file is "hidden" while we run
     */
    if (unlink(tmpfilename) < 0) {
      	perror("configfile_read: unlink()");
	exit(1);
    }
    free(tmpfilename);


    /*
     * pass 0: preprocess file
     *		call the yacc hook, located in y.tab.c
     */

    tw_macro_parse(configfile, fpin, fpout, (struct list **) pp_entry_list);

    if (!specified_configmode)
	(void) fclose(fpin);

    fflush(fpout);
    rewind(fpout);
    fpin = fpout;
    if ((err = ftell(fpin)) != 0) {
	die_with_err("configfile_read: ftell()", NULL);
    }

    /* do we just print out the file, and then exit? */
    if (printpreprocess) {
	int t;

	while ((t = getc(fpin)) != EOF)
	  putc((char) t, stdout);
	exit(0);	
    }

ALREADY_PREPROCESSED:			/* LABEL */
	;

    /* pass 1: get all of the prune entries '!' */
    while (fgets(s, sizeof(s), fpin) != NULL) {

	int prune_mode;
	static int linenumber = 1;

	/* read in database entry */
	if ((err = sscanf(s, "%s %s", filename, ignorestring)) == 1) {
	    (void) strcpy(ignorestring, defaultignore);
	}
	else if (err != 2) {
	    fprintf(stderr, 
		"configfile_read: parse error in the following line\n");
	    fprintf(stderr, "\t>> %s", s);

	    exit(1);
	}
	linenumber++;

	/* check for removeflag (preceding "!" or "=") */
	switch (*filename) {
      	case '!':
	    prune_mode = PRUNE_ALL;
	    (void) strcpy(filename, filename+1);	/* adjust name */
  	    break;
        case '=':
	    prune_mode = PRUNE_ONE;
	    (void) strcpy(filename, filename+1);	/* adjust name */
	    break;
        default:
	  continue; /* nothing */
	}


	/* check for fully qualified pathname
	 */
	if (*filename != '/') {
	    fprintf(stderr,
		"config: %s is not fully qualified!  Skipping...\n" ,
			filename);
	    /* XXX -- error handling needed here */
	    continue;
	}

	/* expand any escaped octal characters in name */
	filename_escape_expand(filename);

	/* add to local prune list */
	list_set(filename, "", 0, &prune_list);
	SPDEBUG(1000) printf("configfile_read: pruning %s\n", filename);

	/* set appropriate prune flag */
	list_setflag(filename, prune_mode, &prune_list);
    }

    /* rewind the file for pass 2 */
    rewind(fpin);

    /* pass 2: build file lists */

    /* it's time for another banner */
    if (!printpreprocess && !quietmode)
	fputs("### Phase 2:   Generating file list\n", stderr);

    while (fgets(s, sizeof(s), fpin) != NULL) {
	int	howdeep;
	int	prunedir = 0;

	/*
	 * get {filename,ignore} pair:
	 * 	if only argument, then apply default ignore-flags
	 *
	 *	note that {ignore} used in the tripwire.config file is
	 *		different than the one stored in the database file!
	 *
	 *	humans use the [N|R|L]+/-[pinugsmc3] format.  in the database,
	 *		we use the old style where any capitalized letter
	 *		means it's to be ignored.
	 */

	/* make sure to remember that the ignorestring could be a comment! */
	if ( ((err = sscanf(s, "%s %s", filename, ignorestring)) == 1) ||
			(ignorestring[0] == '#')) {
	    (void) strcpy(ignorestring, defaultignore);
	}
	else if (err != 2) {
	    fprintf(stderr, "'%s'\nconfigfile_read: parse error\n", s);

	    exit(1);
	}

	/* skip all prune entries (we've already taken care of it) */
	if (*filename == '!')
	    continue;

	/* check for leading '=', prune after one recursion */
	else if (*filename == '=') {
	    (void) strcpy(filename, filename+1);
	    prunedir++;
	}

	/* check for fully qualified pathname
	 */
	if (*filename != '/') {
	    fprintf(stderr,
		"config: %s is not fully qualified!  Skipping...\n" ,
			filename);
	    /* XXX -- error handling needed here */
	    continue;
	}

	/* expand any escaped octal characters in name */
	filename_escape_expand(filename);

	/*
	 * convert configuration-file style ignore-string to our database
	 * representation.
	 */
	ignore_configvec_to_dvec(ignorestring);

	/* add it to the list while it still has escaped characters */
	sprintf(number, "%d %s", entrynum, ignorestring);
	list_set(filename, number, 0, pp_entry_list);
	SPDEBUG(1000) 
	printf("configfile_read: adding %s (%d)\n", filename, number);

	/* reverse index (number --> entryname) */
	{
	    char eindex[50];
	    sprintf(eindex, "%d", entrynum);
	    list_set(eindex, filename, 0, pp_entry_list);
	    list_setflag(eindex, 1, pp_entry_list);
	}

	/* pass down the priority -- based on how fully-qualified the
	 * 	entry was.
	 */
	howdeep = slash_count(filename);

	/*
	 * add the entry to list of entry headers (used for incremental
	 * database updates.
	 */
	configfile_descend(filename, ignorestring, howdeep, prunedir,
					pp_list, entrynum++);
    }						/* end reading file */

    /* print out the list, if we're in a debuggin mode */
    if (debuglevel > 10)
	list_print(pp_list);

    /* clean up */
    if (!specified_configmode)
	(void) fclose(fpin);

    rewind(fpout);
    return;
}

/*
 * configfile_descend(char *filename, char *ignorestring, int howdeep,
 *				int prunedir, struct list **pp_list,
 *				int entrynum)
 *
 *	recurses down the specified filename.  when it finally hits a real
 *	file, it is added to the list of files.
 *	
 *	if (prunedir) is set, then we quit after one recursion.
 *
 *	this routine also resolves any multiple instances of a file by
 *	using (howdeep) as a precendence level.
 *
 *	(entrynum) is the unique entry number tag from tw.config.
 */

static void
configfile_descend (filename, ignorestring, howdeep,
				prunedir, pp_list, entrynum)
    char *filename;
    char *ignorestring;
    int howdeep;
    int prunedir;
    struct list **pp_list;
    int entrynum;
{
    struct stat statbuf;
    static int	countrecurse = 0;	/* count how many levels deep we are */
    static int	majordev, minordev;
    char t[512];
    extern int  errno;

    countrecurse++;

SPDEBUG(10)
printf("---> %d: %s\n", countrecurse, filename);

    /* check to see if it's on the prune list */
    if (list_lookup(filename, &prune_list) != NULL) {

	int flag;

	/* return only if it was a '!' directive */
	if ((flag = list_getflag(filename, &prune_list)) == PRUNE_ALL) {
	    countrecurse--;
	    return;
	}
	else if (flag == PRUNE_ONE)
	    prunedir = 1;
    }

    /* get the stat structure of the (real) file */
    if (lstat(filename, &statbuf) < 0) {
	char err[MAXPATHLEN+256];
        int real_err = errno;  /* in case sprintf clobbers the value */
		
	if (debuglevel > 10) {
	    sprintf(err, "configfile_descend: lstat(%s)", filename);
	} else {
	    sprintf(err, "%s: %s", progname, filename);
	}
	errno = real_err;
	if (!quietmode)
	    perror(err);

	/* so we just skip it */
	countrecurse--;
	return;
    }

    /*
     * record our {major,minor} device pair if this is our first time
     * recursing.  then we check if it changes.  if it does, we've crossed
     * a filesystem, and we prune our tree.
     */
    if (countrecurse == 1) {

SPDEBUG(4)
printf("configfile_descend: r=%d: %s\n", countrecurse, filename);

	majordev = major(statbuf.st_dev);
	minordev = minor(statbuf.st_dev);
    } else {
#ifdef apollo
	/*
	 * It seems that Apollos have (3904,0) for dirs, (3904,1) for files.
	 * So how do we prevent ourselves from crossing filesystems
	 * (descending into mounted disks)?
	*/
	if ((major(statbuf.st_dev) != majordev ||
		minor(statbuf.st_dev) != minordev) &&
		! ( majordev == 3904 &&
		    minordev == 0 &&
		    major(statbuf.st_dev) == 3904 &&
		    minor(statbuf.st_dev) == 1 ) &&
		! ( majordev == 3904 &&
		    minordev == 1 &&
		    major(statbuf.st_dev) == 3904 &&
		    minor(statbuf.st_dev) == 0 ))
#else
	if (major(statbuf.st_dev) != majordev ||
		minor(statbuf.st_dev) != minordev)
#endif
	{

SPDEBUG(4)
printf("configfile_descend: pruning '%s' n(%d,%d) != o(%d, %d)\n", filename,
			major(statbuf.st_dev), minor(statbuf.st_dev),
			majordev, minordev);

	    countrecurse--;
	    return;
	    /* prune */
	}
    }

    /*
     * if it is a directory file, then we read in the directory entries
     * and then recurse into the directory.
     *
     * remember, check to see if it's a symbolic link.  we never traverse
     * them.
     */
    if (((statbuf.st_mode & S_IFMT) == S_IFDIR)

#if !defined(SYSV) || (SYSV > 3)
	&& !((statbuf.st_mode & S_IFMT) == S_IFLNK))
#else
	)
#endif
    {
	DIR *p_dir;

#ifdef DIRENT
	struct dirent *pd;
#else
	struct direct *pd;
#endif

	char recursefile[MAXPATHLEN+256];

	/* handle prunedir flag */

	/*
	 * concatenate entry number to the ignore-string
	 */

	sprintf(t, "%d %s", entrynum, ignorestring);

	/*
	 * just nix it from the list?
	 */

	/* XXX 
	if (strcmp(filename, "/tmp") == 0)
		;
	if (strcmp(filename, "/tmp") == 0)
		list_print(pp_list);
	*/

	/*
	 * Remember: we have escaped filenames (i.e. filenames with
	 * funny characters replaced with \123 sequences) in cf and db
	 * files, and maybe in some report messages (to avoid messing
	 * up silly terminals that cannot cope with those characters;
	 * why do people then have such files?), but internally we save
	 * them in all their gory detail. Otherwise it would be too
	 * hard to keep track of where to convert a name, or if it has
	 * been converted already; in particular we screwed up on
	 * saving the same way for list_set and list_set_flag.
	 */
	/*zzzzz Was: remember, we save filenames with escape sequences in the lists zzzzz*/
	list_set(filename, t, howdeep, pp_list);
	SPDEBUG(1000) printf("configfile_descend: adding %s\n", filename);

	(void) list_setflag(filename, FLAG_NOOPEN, pp_list);

	/* if it's a symbolic link, make sure we flag it as such! */

#if !defined(SYSV) || (SYSV > 3)
	if ((statbuf.st_mode & S_IFMT) == S_IFLNK) {
	    (void) list_setflag(filename, FLAG_SYMLINK, pp_list);
	}
#endif

	if (prunedir) {
	    countrecurse--;
	    return;
	}

SPDEBUG(4)
fprintf(stderr, "configfile_descend: %s: it's a directory!\n", filename);

	if ((p_dir = opendir(filename)) == NULL) {
	    if (debuglevel > 10) {
		perror("configfile_descend: opendir()");
	    } else {
		char err[MAXPATHLEN+256];
		int real_errno = errno;
		
		sprintf(err, "%s: %s", progname, filename);
		errno = real_errno;
		if (!quietmode)
		    perror(err);
	    }
	    countrecurse--;
	    return;
	}


/* broken xenix compiler returns "illegal continue" ?!? */
#ifdef XENIX
#define XCONTINUE goto XENIX_CONT
#else
#define XCONTINUE continue
#endif

	for (pd = readdir(p_dir); pd != NULL; pd = readdir(p_dir)) {
	    /* we could use strcmp in the following, but this is much faster */
	    if (pd->d_name[0] == '.') {
	      if (pd->d_name[1] == 0)    /* must be . */
		XCONTINUE;
	      else if (pd->d_name[1] == '.') {
		if (pd->d_name[2] == 0)  /* must be .. */
		  XCONTINUE;
	      }
	    }
	
SPDEBUG(4)
printf("--> descend: %s\n", pd->d_name);

	    /* build pathname of file */
            /* Assume all filenames ar root anchored.
               If so, and filename[1] is null, then filename must be
               '/'. Thus we don't need to concatenate a slash
               into the recursefile. */
  
	    if (filename[1] == '\0') {
		sprintf(recursefile, "%s%s", filename, pd->d_name);
	    } else {
		sprintf(recursefile, "%s/%s", filename, pd->d_name);
	    }
            
  
            /* recurse.  it'll pop right back if it is just a file */
            configfile_descend(recursefile, ignorestring, howdeep, 0,
					pp_list, entrynum);

XENIX_CONT: ;
	
	} 					/* end foreach file */

	/* cleanup */
	closedir(p_dir);
    }						/* end if dir */
    else {

	/*
	 * concatenate entry number to the ignore-string
	 */

	sprintf(t, "%d %s", entrynum, ignorestring);

	/* add to list */
	list_set(filename, t, howdeep, pp_list);

	/*
	 * if it is a special file or device, add it to the list, but
	 * make sure we don't open it and read from it!
	 */
	switch (statbuf.st_mode & S_IFMT) {
	  case S_IFIFO:
	  case S_IFCHR:
	  case S_IFBLK:
#if !defined(SYSV) || (SYSV > 3)
#ifndef apollo
/* Foolish Apollos define S_IFSOCK same as S_IFIFO in /bsd4.3/usr/include/sys/stat.h */
	  case S_IFSOCK:
#endif
#endif
	    (void) list_setflag(filename, FLAG_NOOPEN, pp_list);
	    break;
#if !defined(SYSV) || (SYSV > 3)
	  case S_IFLNK:	/* if it's a symbolic link, make sure we flag it as such! */
	    (void) list_setflag(filename, FLAG_SYMLINK, pp_list);
	    break;
#endif
	  default:
	    break;   /* do nothing for regular files */
	}
    }						/* end else dir */

    countrecurse--;
    return;
}

