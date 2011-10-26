#ifndef lint
static char rcsid[] = "$Id: main.c,v 1.31 1994/08/26 08:23:03 gkim Exp $";
#endif

/************************************************************************
 *
 *   All files in the distribution of Tripwire are Copyright 1992, 1993 by 
 *   the Purdue Research Foundation of Purdue University.  All rights
 *   reserved.  Some individual files in this distribution may be covered
 *   by other copyrights, as noted in their embedded comments.
 *
 *   Redistribution and use in source and binary forms are permitted
 *   provided that this entire copyright notice is duplicated in all such
 *   copies, and that any documentation, announcements, and other
 *   materials related to such distribution and use acknowledge that the
 *   software was developed at Purdue University, W. Lafayette, IN by
 *   Gene Kim and Eugene Spafford.  No charge, other than an "at-cost"
 *   distribution fee, may be charged for copies, derivations, or
 *   distributions of this material without the express written consent
 *   of the copyright holder.  Neither the name of the University nor the
 *   names of the authors may be used to endorse or promote products
 *   derived from this material without specific prior written
 *   permission.  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY
 *   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE
 *   IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR ANY PARTICULAR
 *   PURPOSE.
 *
 ************************************************************************/

/*
 * main.c
 *
 *	main routines and global variables
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef MALLOCH
# include <malloc.h>
#endif
#include <assert.h>
#if (defined(SYSV) && (SYSV < 3))
# include <limits.h>
#endif	/* SVR2 */
#include "../include/list.h"
#include "../include/tripwire.h"
#include "../include/patchlevel.h"

#ifndef L_tmpnam
# define L_tmpnam (unsigned int) MAXPATHLEN
#endif

/* version information */

char *version_num = VERSION_NUM;
int db_version_num = DB_VERSION_NUM;

/******* signature functions *****************************************
 *	sig_md5_get		: MD5 by RSA
 *	sig_snefru_get		: Snefru by Xerox
 *	sig_null_get		: null
 *********************************************************************/

int (*pf_signatures [NUM_SIGS]) () = {
					SIG0FUNC,
					SIG1FUNC,
					SIG2FUNC,
					SIG3FUNC,
					SIG4FUNC,
					SIG5FUNC,
					SIG6FUNC,
					SIG7FUNC,
					SIG8FUNC,
					SIG9FUNC
				      };
char *signames[NUM_SIGS] = {
					SIG0NAME,
					SIG1NAME,
					SIG2NAME,
					SIG3NAME,
					SIG4NAME,
					SIG5NAME,
					SIG6NAME,
					SIG7NAME,
					SIG8NAME,
					SIG9NAME
				      };

char *config_file = CONFIG_FILE;
char *database_file = DATABASE_FILE;

char *database_path = DATABASE_PATH;
char *config_path = CONFIG_PATH;

char tempdatabase_file[MAXPATHLEN+256];
FILE *fptempdbase;

char *defaultignore = DEFAULTIGNORE;
static char *defaultignore_parsed;

char *db_record_format = DB_RECORD_FORMAT;

struct list *olddbase_list = (struct list *) NULL;

int debuglevel = 1;
int verbosity = 0;
int loosedir = 0;
static int dbaseinit = 0;
int printhex = 0;
static char **pp_updateentries = NULL;
static int numupdateentries = 0;
int quietmode = 0;
int printpreprocess = 0;
char *specified_dbasefile = NULL;
char *specified_configfile = NULL;
int specified_configfd = -1;
int specified_dbasefd = -1;

/* if these vars are non-zero, specified_fd is guaranteed to be valid */
int specified_dbasemode = 0;
int specified_configmode = 0;

int runtimeignore = 0;
int interactivemode = 0;
int test_interactive = 0;

char *progname;

void cleanup();

static void
usage()
{
    fputs("usage: tripwire [ options ... ]\n", stderr);
    fputs("\tWhere `options' are:\n", stderr);
    fputs("\t\t-initialize	Database Generation mode\n", stderr);
    fputs("\t\t-init		\n", stderr);
    fputs("\t\t-update entry	update entry (a file, directory, or \n", stderr);
    fputs("\t\t		    tw.config entry) in the database\n", stderr);
    fputs("\t\t-interactive	Integrity Checking mode with\n", stderr);
    fputs("\t\t		    Interactive entry updating\n", stderr);
    fputs("\t\t-loosedir	use looser checking rules for directories\n", stderr);
    fputs("\t\t-d dbasefile	read in database from dbasefile\n", stderr);
    fputs("\t\t		    (use `-d -' to read from stdin)\n", stderr);
    fputs("\t\t-c configfile	read in config file from configfile\n", stderr);
    fputs("\t\t		    (use `-c -' to read from stdin)\n", stderr);
    fputs("\t\t-cfd fd	    read in config file from specified fd\n", stderr);
    fputs("\t\t-dfd fd	    read in the database file from specified fd\n", stderr);
    fputs("\t\t-Dvar=value	define a tw.config variable (ala @@define)\n",
	stderr);
    fputs("\t\t-Uvar		undefine a tw.config variable (ala @@undef)\n",
	stderr);
    fputs("\t\t-i #|all 	ignore the specified signature (to reduce\n", stderr);
    fputs("\t\t		    execution time)\n", stderr);
    fputs("\t\t-q		quiet mode\n", stderr);
    fputs("\t\t-v		verbose mode\n", stderr);
    fputs("\t\t-preprocess	print out preprocessed configuration file\n",
	stderr);
    fputs("\t\t-E		\n", stderr);
    fputs("\t\t-help		print out interpretation help message\n", stderr);
    fputs("\t\t-version	print version and patch information\n", stderr);
    exit(1);
}

/*
 * void
 * version()
 *
 *	print out version information, with patchlevel information.
 *	currently, there is no real correlation between the two.
 */

static void
version()
{
    fprintf(stderr, "\nTripwire version %s (patchlevel %d)\n\n", version_num,
			    PATCHLEVEL);
    fprintf(stderr, "Copyright (c) 1992, 1993, 1994 Purdue Research Foundation\n");
    fprintf(stderr, "\tBy Gene Kim, Eugene Spafford\n\n");
    exit(0);
}

int
main(argc, argv)
    int argc;
    char *argv[];
{
    int i, fd;
    char *pc;
    char database[MAXPATHLEN+256];
    char mask[64];
    char *specified_fd;
    int exitstatus = 0;

    progname = argv[0];

    /* iterate through arguments */
    for (i = 1; i < argc; i++) {
	pc = argv[i];
	/* verbose mode */
	if (strcmp(pc, "-v") == 0) {
	    verbosity++;
	    continue;
	}
	/* quiet mode */
	if (strcmp(pc, "-q") == 0) {
	    quietmode++;
	    continue;
	}
	/* hex mode */
	if (strcmp(pc, "-x") == 0) {
	    printhex++;
	    continue;
	}
	/* database generation mode */
	if (strcmp(pc, "-initialize") == 0 || strcmp(pc, "-init") == 0 ||
					      strcmp(pc, "-initialise") == 0) {
	    dbaseinit++;
	    continue;
	}
	/* print preprocessed configuration file */
	if ((strcmp(pc, "-preprocess") == 0) || (strcmp(pc, "-E") == 0)) {
	    printpreprocess++;
	    continue;
	}
	/* update specific database entry */
	if (strcmp(pc, "-update") == 0) {
	    /* check to see that there is an argument */
	    if ((pc = argv[++i]) == NULL) {
		usage();
	    }
	    /* exhaust the argument list */
	    while (pc) {
		if (pp_updateentries == NULL) {
		    if ((pp_updateentries = (char **) malloc(sizeof(char *))) 
		    			== NULL) {
		        die_with_err("main: malloc() failed!\n", NULL);
		    }
		} else 
		if ((pp_updateentries = (char **) realloc(pp_updateentries,
			(numupdateentries+1) * sizeof(char *))) == NULL) {
		    die_with_err("main: realloc() failed!\n", NULL);
		}
		pp_updateentries[numupdateentries++] = pc;
		pc = argv[++i];
	    }
	    continue;
	}
	/* specify database file */
	if (strcmp(pc, "-d") == 0) {
	    /* check to see that there is an argument */
	    if ((pc = argv[++i]) == NULL) {
		usage();
	    }
	    specified_dbasefile = pc;
	    specified_dbasemode |= SPECIFIED_FILE;
	    continue;
	}
	/* specify configuration file */
	if (strcmp(pc, "-c") == 0) {
	    /* check to see that there is an argument */
	    if ((pc = argv[++i]) == NULL) {
		usage();
	    }
	    specified_configfile = pc;
	    specified_configmode |= SPECIFIED_FILE;
	    continue;
	}
	/* specify configuration file descriptor */
	if (strcmp(pc, "-cfd") == 0) {
	    char err[512];

	    /* check to see that there is an argument */
	    if ((pc = argv[++i]) == NULL) {
		usage();
	    }
	    specified_fd = pc;
	    if (!sscanf(specified_fd, "%d", &specified_configfd)) {
		usage();
	    }
	    /* if we try to read stdin, we'll block, so skip read */
	    if (specified_configfd != 0 &&
				fcntl(specified_configfd, F_GETFL, 0) < 0) {
		sprintf(err, "tripwire: Couldn't open fd %d!  fcntl()", 
			specified_configfd);
		perror(err);
		exit(1);
	    }
	    specified_configmode |= SPECIFIED_FD;
	    continue;
	}
	/* specify dbase file descriptor */
	if (strcmp(pc, "-dfd") == 0) {
	    char err[512];

	    /* check to see that there is an argument */
	    if ((pc = argv[++i]) == NULL) {
		usage();
	    }
	    specified_fd = pc;
	    if (!sscanf(specified_fd, "%d", &specified_dbasefd)) {
		usage();
	    }
	    /* if we try to read stdin, we'll block, so skip read */
	    if (specified_dbasefd != 0 &&
				fcntl(specified_dbasefd, F_GETFL, 0) < 0) {
		sprintf(err, "tripwire: Couldn't open fd %d!  fcntl()", 
			specified_dbasefd);
		perror(err);
		exit(1);
	    }
	    specified_dbasemode |= SPECIFIED_FD;
	    continue;
	}
	/* ignore specified signatures */
	if (strcmp(pc, "-i") == 0) {
	    int tmpflag;

	    /* check to see if there is an argument */
	    if ((pc = argv[++i]) == NULL) {
		usage();
	    }
	    if (strcmp(pc, "all") == 0) {
		runtimeignore = IGNORE_0_9;
		continue;
	    }
	    if ((sscanf(pc, "%d", &tmpflag)) != 1)
		usage();
	    runtimeignore |= (IGNORE_0 << tmpflag);
	    continue;
	}
	/* ignore specified signatures */
	if (strcmp(pc, "-debug") == 0) {
	    /* check to see if there is an argument */
	    if ((pc = argv[++i]) == NULL) {
		usage();
	    }
	    if ((sscanf(pc, "%d", &debuglevel)) != 1)
		usage();
	    continue;
	}
	/* print out version information */
	if (strcmp(pc, "-version") == 0) {
	    version();
	}
	/* loosedir rules */
	if (strcmp(pc, "-loosedir") == 0) {
	    loosedir = 1;
	    continue;
	}
	/* print out version information */
	if (strcmp(pc, "-help") == 0) {
	    tw_help_print(stderr);
	    exit(0);
	}
	/* interactive mode */
	if (strcmp(pc, "-interactive") == 0) {
	    interactivemode++;
	    continue;
	}
	/* define (-Dfoo=bar) */
	if (strncmp(pc, "-D", 2) == 0) {
	    char key[512], value[512];

	    if (!pc[2]) {
		fputs("tripwire: -D requires an argument!\n", stderr);
		exit(1);
	    }
	    (void) string_split_ch(pc+2, key, value, '=');
	    tw_mac_define(key, value);
	    continue;
	}
	/* undef (-Ufoo) */
	if (strncmp(pc, "-U", 2) == 0) {
	    if (!pc[2]) {
		fputs("tripwire: -U requires an argument!\n", stderr);
		exit(1);
	    }
	    tw_mac_undef(pc+2);
	    continue;
	}
	/* undocumented: test interactive mode */
	if (strcmp(pc, "-interactivetest_yesimsure") == 0) {
	    test_interactive = 1;
	    continue;
	}
	usage();
    }

    /* argument sanity checking */

    /* eliminate aliases of stdin 
     * 	(our canonical form is using fd 0)
     */
    if (specified_dbasefile && strcmp(specified_dbasefile, "-") == 0) {
        specified_dbasefd = 0;
	specified_dbasemode = SPECIFIED_FD;
	specified_dbasefile = NULL;
    }
    if (specified_configfile && strcmp(specified_configfile, "-") == 0) {
        specified_configfd = 0;
	specified_configmode = SPECIFIED_FD;
	specified_configfile = NULL;
    }

    /* are two files set to read from stdin? */
    if (specified_configfd == 0 && specified_dbasefd == 0) {
	fprintf(stderr, "%s: specified database and configuration file can't be both be stdin!\n", progname);
	exit(1);
    }

    /* interactive mode and update mode? */
    if (interactivemode && pp_updateentries) {
        fprintf(stderr, "%s: conflicting mode directives!  Aborting...\n",
		progname);
	exit(1);
    }
    /* specified configfile and configfd? */
    if ((specified_configmode & SPECIFIED_FILE) &&
		(specified_configmode & SPECIFIED_FD)) {
	fprintf(stderr, "%s: specified file and file descriptor for configuration file!\n", progname);
	exit(1);
    }
    /* specified dbasefile and dbasefd? */
    if ((specified_dbasemode & SPECIFIED_FILE) &&
		(specified_dbasemode & SPECIFIED_FD)) {
	fprintf(stderr, "%s: specified file and file descriptor for database file!\n", progname);
	exit(1);
    }

    /* specified dbasefile and initialize dbase mode */
    if (specified_dbasemode && dbaseinit) {
	if (!quietmode) {
	    fprintf(stderr, "%s: specifying a database file in database initialization mode \n", progname);
	    fprintf(stderr, "\tis meaningless.  Ignoring specified file...\n");
	}
    }

    /*** we check any specified file descriptors to make sure they are
     *** files.  if not, we copy them into /tmp and return its fd.
     *** (we unlink them as soon as we create them.)
     ***/

    switch(specified_dbasemode) {
    case SPECIFIED_NONE:
    	break;
    case SPECIFIED_FILE:
        specified_dbasefd = file_copy_to_tmp(specified_dbasefile);
	break;
    case SPECIFIED_FD:
        specified_dbasefd = fd_copy_to_tmp(specified_dbasefd);
	break;
    default:
        die_with_err("illegal specified_dbasemode state", NULL);
    }

    switch(specified_configmode) {
    case SPECIFIED_NONE:
    	break;
    case SPECIFIED_FILE:
        specified_configfd = file_copy_to_tmp(specified_configfile);
	break;
    case SPECIFIED_FD:
        specified_configfd = fd_copy_to_tmp(specified_configfd);
	break;
    default:
        die_with_err("illegal specified_configmode state", NULL);
    }

    /* initialize lists */
    list_init();

    /* build hostname specific names */
    filename_hostname_expand(&config_path);
    filename_hostname_expand(&config_file);
    filename_hostname_expand(&database_path);
    filename_hostname_expand(&database_file);

    /* recompute the default ignore string (old -> new format) */
    (void) strcpy(mask, defaultignore);
    ignore_configvec_to_dvec(mask);
    defaultignore_parsed = mask;
    
    /* if we are creating a database, make sure the database troving directory
     * exist.
     */
#define DATABASE_REPOSITORY "./databases"

    if (dbaseinit || interactivemode || numupdateentries > 0) {
	if ((fd = open(DATABASE_REPOSITORY, 0)) >= 0) {
	    close(fd);
	} else {
	    if (mkdir(DATABASE_REPOSITORY, 0777) >= 0) {
		if (!quietmode) {
		    fprintf(stderr, "### Warning:\tcreating %s directory!\n",
					DATABASE_REPOSITORY);
		    fprintf(stderr, "###\n");
		}
	    } else {
		char errstr[1024];
		sprintf(errstr, "%s: mkdir(%s)", progname, DATABASE_REPOSITORY);
		perror(errstr);
		exit(1);
	    }
	}
    }

    /* are we in database generation mode? */
    if (dbaseinit) {
	char *oldpath = database_path;
	char *newpath = database_path = "./databases";
	struct list *dbase_entry_list = (struct list *) NULL;

	/* place database in ./databases */
	database_path = newpath;

	/* generate the database */
	configfile_read(&olddbase_list, &dbase_entry_list);
	database_build(&olddbase_list, DBASE_PERMANENT, &dbase_entry_list);
	if (!quietmode) {
	    fprintf(stderr, "###\n");
	    fprintf(stderr,
"### Warning:   Database file placed in %s/%s.\n", database_path,
							database_file);
	    fprintf(stderr, "###\n");
	    fprintf(stderr,
"###            Make sure to move this file file and the configuration\n");
	    fprintf(stderr,
"###            to secure media!\n");
	    fprintf(stderr, "###\n");
	    fprintf(stderr,
"###            (Tripwire expects to find it in '%s'.)\n", oldpath);
	}
	cleanup();
	exit(0);
    }

    /*
     * 	make sure that database file is there!
     * 		(this is meaningless if we specified stdin "-")
     */

    switch(specified_dbasemode) {
    case SPECIFIED_NONE:
	    sprintf(database, "%s/%s", database_path, database_file);
	    break;
    case SPECIFIED_FILE:
	    (void) strcpy(database, specified_dbasefile);
	    break;
    case SPECIFIED_FD:
	    break;
    }

    if (!printpreprocess && (specified_dbasemode != SPECIFIED_FD)) {
	if ((fd = open(database, O_RDONLY)) < 0) {
	    /* make sure our error message is correct */
	    if (errno != ENOENT) {
		char err[1024];
		sprintf(err, "%s: database file `%s'", progname, database);
		perror(err);
		exit(1);
	    }
	    fprintf(stderr,
		    "%s: database file '%s' does not exist!  Aborting...\n",
		    progname, database);
	    exit(1);
	}
	(void) close(fd);
    }

    /* are we in database update mode? */
    if (numupdateentries) {
	update_mark(pp_updateentries, numupdateentries);
	cleanup();
	exit(0);
    }

    /* we're in integrity checking mode */
    update_gather(interactivemode, &pp_updateentries);
    /* do we do the interactive update? */
    if (interactivemode && pp_updateentries) {
	list_reset(&olddbase_list);
	list_reset(&diff_added_list);
	list_reset(&diff_deleted_list);
	list_reset(&diff_changed_list);

	/* reset the ignore flags so we scan all signatures */
	runtimeignore = 0;

	for (i = 0, pc = pp_updateentries[i]; pc; i++, 
					    pc = pp_updateentries[i]) {
SPDEBUG(0) 
printf("Updating entry: %s\n", filename_escape(pc));
	}
	numupdateentries = i;

	if (!quietmode) {
	    fprintf(stderr, "### Updating database...\n###\n");
	}
	update_mark(pp_updateentries, numupdateentries);
	cleanup();
	if (!quietmode) {
	    fprintf(stderr, "###\n");
	    fprintf(stderr, "### If you changed the tw.config file, remember to run `twdb_check.pl' to\n");
	    fprintf(stderr, "### ensure database consistency.\n");
	    fprintf(stderr, "### See the README file for details.\n");
	}
	exit(0);
    }

    cleanup();

    /* our exit status is based on files added/deleted/changed */
    if (diff_added_num)
	exitstatus |= 2;
    if (diff_deleted_num)
	exitstatus |= 4;
    if (diff_unignored_num)
	exitstatus |= 8;
    exit(exitstatus);
    /*NOTREACHED*/
}

void
cleanup()
{
    /* delete temporary database file (derived from specified dbasefd) */
    /*
    if (specified_dbasefd >= 0) {
	unlink(specified_dbasefile);
    }
    */
}

