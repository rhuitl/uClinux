#ifndef lint
static char rcsid[] = "$Id: preen.report.c,v 1.20 1994/08/04 03:44:34 gkim Exp $";
#endif

/*
 * preen.report.c
 *
 *	report generation given the data from preening
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
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#include <time.h>
#ifdef MALLOCH
# include <malloc.h>
#endif
#include "../include/list.h"
#include "../include/tripwire.h"

static void preen_report_changed_enum();
static int preen_change_count();
static char *structstat_fill();
static void pair_print_ss();
static void pair_print_ll();
static void pair_print_llo();
static char **pp_update = (char **) NULL;
static void updateentry_prompt();
static void updateentry_menu();
static void updateentry_help();
static int entrynum_get();

/*
 * preen_report()
 *
 *	report on:
 *		which files have been ADDED
 *		which files have been DELETED
 *		which files have been CHANGED
 *			what attribute changed?
 *
 *	remember that (olddbase_list) is composed of filenames that
 *	have not been expanded.
 */

void
preen_report(interactive, ppp_updateentries)
    int interactive;
    char ***ppp_updateentries;
{
    struct list_elem *p;
    struct stat statnew, statold;
    char sigsnew[NUM_SIGS][SIG_MAX_LEN], sigsold[NUM_SIGS][SIG_MAX_LEN];
    char *s;
    int unignored;
    FILE *fttyin = NULL, *fttyout = NULL;

    /* we'll use a local variable for this */
    /*
    pp_update = *ppp_updateentries;
    */

    /* if we're in interactive mode, open tty for input */
    if (interactive) {
	if ((fttyin = fopen("/dev/tty", "r")) == NULL) {
	    char err[256];
	    sprintf(err, "%s: cannot fopen() /dev/tty", progname);
	    perror(err);
	    exit(1);
	}
	if ((fttyout = fopen("/dev/tty", "w")) == NULL) {
	    char err[256];
	    sprintf(err, "%s: cannot fopen() /dev/tty", progname);
	    perror(err);
	    exit(1);
	}
    }

    unignored = preen_change_count();

    if (!quietmode) {
    fprintf(stderr, "###\n");
    fprintf(stderr, "###\t\t\tTotal files scanned:\t\t%d\n", files_scanned_num);
    fprintf(stderr, "###\t\t\t      Files added:\t\t%d\n", diff_added_num);
    fprintf(stderr, "###\t\t\t      Files deleted:\t\t%d\n", diff_deleted_num);
    fprintf(stderr, "###\t\t\t      Files changed:\t\t%d\n", diff_changed_num);
    fprintf(stderr, "###\n");
    fprintf(stderr, "###\t\t\tAfter applying rules:\n");
    fprintf(stderr, "###\t\t\t      Changes discarded:\t%d\n",
			diff_added_num + diff_deleted_num + diff_changed_num -
	      		(unignored) );
    fprintf(stderr, "###\t\t\t      Changes remaining:\t%d\n",
		        unignored + diff_added_num + diff_deleted_num);
    fprintf(stderr, "###\n");
    }

    /****** added ******/

    /* open each of the three lists, using &diff_xxxx_list as keys */
    if (list_open(&diff_added_list) < 0) {
	fprintf(stderr, "preen_report: list_open() failed!\n");
	exit(1);
    }

    /* print out each added file in sequence */
    while ((p = list_get(&diff_added_list)) != NULL) {
	static int firsttime = 1;
	char filename[2048];

	strcpy(filename, p->varname);

	(void) structstat_fill(p->varvalue, &statnew, sigsnew, filename);

	direntry_print(filename, statnew, DIFF_ADDED);

	/* XXX: Why are some people seeing files in the added and deleted
	 * list.  Abort if this happens.
	 */
	if (list_isthere(filename, &diff_deleted_list)) {
	    printf("### Why is this file also marked as DELETED?  Please mail this output to (gkim@cs.purdue.edu)!\n");
	}
	if (list_isthere(filename, &diff_changed_list)) {
	    printf("### Why is this file also marked as CHANGED?  Please mail this output to (gkim@cs.purdue.edu)!\n");
	}

	if (interactive) {
	    int entrynum;
	    entrynum = entrynum_get(p->varvalue);
	    updateentry_prompt(fttyin, fttyout, filename, entrynum, firsttime);
	    firsttime = 0;
	}
    }

    if (list_close(&diff_added_list) < 0) {
	fprintf(stderr, "preen_report: list_close() failed!\n");
	exit(1);
    }

    /****** deleted ******/

    /* now print out the files that were deleted */
    if (list_open(&diff_deleted_list) < 0) {
	fprintf(stderr, "preen_report: list_open() failed!\n");
	exit(1);
    }

    /* print out each added file in sequence */
    while ((p = list_get(&diff_deleted_list)) != NULL) {
	static int firsttime = 1;
	char filename[2048];

	strcpy(filename, p->varname);

	(void) structstat_fill(p->varvalue, &statnew, sigsnew, filename);

	direntry_print(filename, statnew, DIFF_DELETED);
	if (interactive) {
	    int entrynum;
	    entrynum = entrynum_get(p->varvalue);
	    updateentry_prompt(fttyin, fttyout, filename, entrynum, firsttime);
	    firsttime = 0;
	}
    }

    if (list_close(&diff_deleted_list) < 0) {
	fprintf(stderr, "preen_report: list_close() failed!\n");
	exit(1);
    }

    /***** changed ******/

    /*
     * interate through the list
     *		get the ignore vector
     *		foreach each (attribute) {
     *			if (attribute != attribute')
     *				if (!ignored) { flag it; }
     *		}
     */
    /*
    list_print(&diff_changed_list);
    */
    if (list_open(&diff_changed_list) < 0) {
	fprintf(stderr, "preen_report: list_open() failed!\n");
	exit(1);
    }

    /* print out each added file in sequence */
    while ((p = list_get(&diff_changed_list)) != NULL) {

	/* filename, ignore, mode, inode, nlinks, uid, gid, size, access,
	 * modify, ctime, sig1, sig2
	 */

	/* read in the new value from the changed_list
	 *		throw away the new ignorevector -- we use the old one!
	 */
	(void) structstat_fill(p->varvalue, &statnew, sigsnew, p->varname);

	/* read in the list1 value form the hash table */
	if ((s = list_lookup(p->varname, &olddbase_list)) == NULL) {
	    fprintf(stderr, "preen_report: list_lookup(%s) failed!\n",
		p->varname);
	    exit(1);
	}

	/* check for unchanged flag */
	if (list_getflag(p->varname, &diff_changed_list) & FLAG_UNCHANGE) {
	    SPDEBUG(6) printf("--(skipping unchanged entry %s)--\n",
					p->varname);
	    continue;
	}

	(void) structstat_fill(s, &statold, sigsold, p->varname);

	/* is this file to be ignored? */
	if (!(list_getflag(p->varname, &diff_changed_list) & FLAG_CHANGED))
	    continue;

	/* print out the report for this file */
	direntry_print(p->varname, statnew, DIFF_CHANGED);

    }

    if (list_close(&diff_changed_list) < 0) {
	fprintf(stderr, "preen_report: list_close() failed!\n");
	exit(1);
    }

    /* enumerate specifics of changed files, if long output specified */
    if (interactive || (!quietmode && unignored != 0)) {
	preen_report_changed_enum(interactive, fttyin, fttyout);
    }

    /* close up the tty streams */
    if (interactive) {
	fclose(fttyin);
	fclose(fttyout);
    }

    *ppp_updateentries = pp_update;
    diff_unignored_num = unignored;
    return;
}

/*
 * preen_report_changed_enum(int interactive, fttyin, fttyout)
 *
 *	enumerate each changed attributed for each of the changed files.
 *	this is treated as yet another pass in the checking process.
 *
 *	(interactive) indicates whether we should be asking the user to 
 *	update this file later.  (fttyin) and (fttyout) are the streams
 *	we talk through.
 */

static void
preen_report_changed_enum(interactive, fttyin, fttyout)
    int interactive;
    FILE *fttyin, *fttyout;
{
    struct list_elem *p;
    char *ignorevec;
    char sigsold[NUM_SIGS][SIG_MAX_LEN], sigsnew[NUM_SIGS][SIG_MAX_LEN];
    struct stat statnew, statold;
    char *s;
    char stime1[64], stime2[64];
    int ignoremask;
    int i;
    char label[50];

    (void) fflush(stdout);
    if (!quietmode) {
	fprintf(stderr, "### Phase 5:   Generating observed/expected pairs for changed files\n");
	fprintf(stderr, "###\n");
	(void) fflush(stderr);
    }

printf("### Attr        Observed (what it is)	      Expected (what it should be)\n");
printf("### =========== ============================= =============================\n");
    /****
    st_atime: Mon Aug 31 16:48:57 1992         Mon Aug 31 14:05:49 1992
    ****/

    /* open the list of changed files */
    if (list_open(&diff_changed_list) < 0) {
	fprintf(stderr, "preen_report: list_open() failed!\n");
	exit(1);
    }

    /* print out each added file in sequence */
    while ((p = list_get(&diff_changed_list)) != NULL) {
        static int firsttime = 1;

	/* filename, ignore, mode, inode, nlinks, uid, gid, size, access,
	 * modify, ctime, sig1, sig2 .. sign
	 */

	/* read in the list2 value from the changed_list
	 *		throw away the new ignorevector -- we use the old one!
	 */
	(void) structstat_fill(p->varvalue, &statnew, sigsnew, p->varname);

	/* read in the list1 value form the hash table */
	if ((s = list_lookup(p->varname, &olddbase_list)) == NULL) {
	    fprintf(stderr, "preen_report_changed_enum: list_lookup(%s) failed!\n", p->varname);
	    exit(1);
	}

	ignorevec = structstat_fill(s, &statold, sigsold, p->varname);

	/* get the ignoremask */
	ignoremask = ignore_vec_to_scalar(ignorevec);

	/* is this file to be ignored? */
	if (!(list_getflag(p->varname, &diff_changed_list) & FLAG_CHANGED))
	    continue;

	printf("%s\n", p->varname);
	/* and then the {expected, received} pairs */

#define STATEQ(x) (statnew.x != statold.x)

	/* if we're reporting growing files, report size */
	if (ignoremask & IGNORE_GROW) {
	    ignoremask = ignoremask & ~(IGNORE_S);
	}

	if (!(ignoremask & IGNORE_P))
	    if (STATEQ(st_mode)) {
		pair_print_llo("st_mode:", (int32) statnew.st_mode,
			(int32) statold.st_mode);
	    }
	
	if (!(ignoremask & IGNORE_I))
	    if (STATEQ(st_ino)) {
		pair_print_ll("st_ino:", (int32) statnew.st_ino,
			(int32) statold.st_ino);
	    }
	
	if (!(ignoremask & IGNORE_N))
	    if (STATEQ(st_nlink)) {
		pair_print_ll("st_nlink:", (int32) statnew.st_nlink,
			(int32) statold.st_nlink);
	    }

	if (!(ignoremask & IGNORE_U))
	    if (STATEQ(st_uid)) {
		pair_print_ll("st_uid:", (int32) statnew.st_uid,
			(int32) statold.st_uid);
	    }

	if (!(ignoremask & IGNORE_G))
	    if (STATEQ(st_gid)) {
		pair_print_ll("st_gid:", (int32) statnew.st_gid,
			(int32) statold.st_gid);
	    }

	if (!(ignoremask & IGNORE_S))
	    if (STATEQ(st_size)) {
		pair_print_ll("st_size:", (int32) statnew.st_size,
			(int32) statold.st_size);
	    }

	if (!(ignoremask & IGNORE_A))
	    if (STATEQ(st_atime)) {
		(void) strcpy(stime1, ctime(&statnew.st_atime));
		(void) strcpy(stime2, ctime(&statold.st_atime));
		chop(stime1);
		chop(stime2);
		pair_print_ss("st_atime:", stime1, stime2);
	    }

	if (!(ignoremask & IGNORE_M))
	    if (STATEQ(st_mtime)) {
		(void) strcpy(stime1, ctime(&statnew.st_mtime));
		(void) strcpy(stime2, ctime(&statold.st_mtime));
		chop(stime1);
		chop(stime2);
		pair_print_ss("st_mtime:", stime1, stime2);
	    }

	if (!(ignoremask & IGNORE_C))
	    if (STATEQ(st_ctime)) {
		(void) strcpy(stime1, ctime(&statnew.st_ctime));
		(void) strcpy(stime2, ctime(&statold.st_ctime));
		chop(stime1);
		chop(stime2);
		pair_print_ss("st_ctime:", stime1, stime2);
	    }

	for (i = 0; i < NUM_SIGS; i++) {
	    if (!(runtimeignore & (IGNORE_0 << i)) &&
					!(ignoremask & (IGNORE_0 << i)))
		if (strcmp(sigsnew[i], sigsold[i]) != 0) {
		    (void) sprintf(label, "%s (sig%d):", signames[i], i);
		    pair_print_ss(label, sigsnew[i], sigsold[i]);
		}

	}

	/* quiz the user if this entry should be updated */
	if (interactive) {
	    int entrynum;
	    entrynum = entrynum_get(p->varvalue);
	    updateentry_prompt(fttyin, fttyout, p->varname, entrynum, firsttime);
	    firsttime = 0;
	}

	/* separate entries by a space */
	printf("\n");

    }

    if (list_close(&diff_changed_list) < 0) {
	fprintf(stderr, "preen_report_changed_enum: list_close() failed!\n");
	exit(1);
    }
}

/*
 * preen_change_count()
 *
 *	return the number of files that are changed, according to their
 *	ignore vectors.
 */

static int
preen_change_count()
{
    int changed = 0;
    struct list_elem *p;
    char sigsold[NUM_SIGS][SIG_MAX_LEN], sigsnew[NUM_SIGS][SIG_MAX_LEN];
    char vec64_a[50], vec64_m[50], vec64_c[50];
    char trash[512];
    struct stat statnew, statold;
    char *s;
    int ignoremask;
    char ignorevec[512];
    uint32 mode, ino, nlink, uid, gid, size;
    int entrynum;
    int nfields;

    /***** changed ******/

    /*
     * interate through the list
     *		get the ignore vector
     *		foreach each (attribute) {
     *			if (attribute != attribute')
     *				if (!ignored) { flag it; }
     *		}
     */
    if (list_open(&diff_changed_list) < 0) {
	fprintf(stderr, "preen_report: list_open(diff_changed_list) failed!\n");
	exit(1);
    }

    /* print out each added file in sequence */
    while ((p = list_get(&diff_changed_list)) != NULL) {

	int isdir = 0;
	int reallychanged = 0;

	/* filename, ignore, mode, inode, nlinks, uid, gid, size, access,
	 * modify, ctime, sig1, sig2
	 */

	/* read in the list2 value from the changed_list
	 *		throw away the new ignorevector -- we use the old one!
	 */

	if ((nfields = sscanf(p->varvalue, db_record_format,
		&entrynum, trash,
		&mode, &ino, &nlink, &uid, &gid, &size,
		vec64_a, vec64_m, vec64_c,
		sigsnew[0], sigsnew[1], sigsnew[2], sigsnew[3], sigsnew[4],
		sigsnew[5], sigsnew[6], sigsnew[7], sigsnew[8], sigsnew[9]))
				!= DB_RECORD_FIELDS) {
	    fprintf(stderr, "preen_change_count: %s: illegal database record (nfields == %d).   Aborting...\n", 
				 p->varname, nfields);
	    fprintf(stderr, "	'%s'\n", p->varvalue);
	    exit(1);
	}
	if ((mode & S_IFMT) == S_IFDIR)
	    isdir = 1;

        statnew.st_mode = (mode_t)mode;
        statnew.st_ino = (ino_t)ino;
        statnew.st_nlink = (nlink_t)nlink;
        statnew.st_uid = (uid_t)uid;
        statnew.st_gid = (gid_t)gid;
        statnew.st_size = (off_t)size;

	/* convert from base64 to int */
	statnew.st_atime = b64tol(vec64_a);
	statnew.st_mtime = b64tol(vec64_m);
	statnew.st_ctime = b64tol(vec64_c);

	/* read in the list1 value form the hash table */
	if ((s = list_lookup(p->varname, &olddbase_list)) == NULL) {
	    fprintf(stderr, "preen_change_count: list_lookup(%s) failed!\n",
			p->varname);
	    exit(1);
	}

	if ((nfields = sscanf(s, db_record_format,
		&entrynum, ignorevec,
		&mode, &ino, &nlink, &uid, &gid, &size,
		vec64_a, vec64_m, vec64_c,
		sigsold[0], sigsold[1], sigsold[2], sigsold[3], sigsold[4],
		sigsold[5], sigsold[6], sigsold[7], sigsold[8], sigsold[9]))
				!= DB_RECORD_FIELDS) {
	    fprintf(stderr, "preen_change_count: %s: illegal database record! Aborting...  (nfields=%d)\n", p->varname, nfields);
	    fprintf(stderr, "	'%s'\n", s);
	    exit(1);
	}
        statold.st_mode = (mode_t)mode;
        statold.st_ino = (ino_t)ino;
        statold.st_nlink = (nlink_t)nlink;
        statold.st_uid = (uid_t)uid;
        statold.st_gid = (gid_t)gid;
        statold.st_size = (off_t)size;

	/* convert from base64 to int */
	statold.st_atime = b64tol(vec64_a);
	statold.st_mtime = b64tol(vec64_m);
	statold.st_ctime = b64tol(vec64_c);

	/* get the ignoremask */
	ignoremask = ignore_vec_to_scalar(ignorevec);

	/* and then the {expected, received} pairs */

#define FLAGIT(x) changed++; reallychanged = 1; SPDEBUG(3) {printf("--(FLAGGING %s: unignored change in <%s>)--\n", p->varname, (x)); } list_setflag(p->varname, FLAG_CHANGED, &diff_changed_list); continue
#define SIGEQ(x) if (strcmp(sigsnew[(x)], sigsold[(x)]) != 0)

	/* allow for loose directory interpretations by ignoring nlink,
	 * ctime, and mtime, and size.
	 */
	if (isdir && loosedir) {
	    ignoremask |= IGNORE_N | IGNORE_M | IGNORE_C | IGNORE_S;
	}
#ifdef apollo
	/*
	 * Apollos do not keep ownership or dates for symlinks, but
	 * get these from the directory containing them (with wide-open
	 * permissions). Ignore these. (Why only if we also have loosedir?)
	 * (Otherwise each symlink would get flagged whenever the directory
	 * is changed, e.g. by adding or deleting a file.)
	 */
	else if (((mode & S_IFMT) == S_IFLNK) && loosedir) {
	    ignoremask |= IGNORE_P | IGNORE_U | IGNORE_G | IGNORE_A | IGNORE_M | IGNORE_C;
	}
#endif

	/* note the pain we go through to avoid dangling else's */
	if (!(ignoremask & IGNORE_P)) { if (STATEQ(st_mode)) {FLAGIT("p");}}
	if (!(ignoremask & IGNORE_I)) { if (STATEQ(st_ino)) {FLAGIT("i");}}
	if (!(ignoremask & IGNORE_N)) { if (STATEQ(st_nlink)) {FLAGIT("n");}}
	if (!(ignoremask & IGNORE_U)) { if (STATEQ(st_uid)) {FLAGIT("u");}}
	if (!(ignoremask & IGNORE_G)) { if (STATEQ(st_gid)) {FLAGIT("g");}}
	if ((ignoremask & IGNORE_GROW)) { if (statnew.st_size < statold.st_size) { ignoremask = ignoremask & ~(IGNORE_S); FLAGIT(">"); ;}}
	if (!(ignoremask & IGNORE_S)) { if (STATEQ(st_size)) {FLAGIT("s");}}
	if (!(ignoremask & IGNORE_A)) { if (STATEQ(st_atime)) {FLAGIT("a");}}
	if (!(ignoremask & IGNORE_M)) { if (STATEQ(st_mtime)) {FLAGIT("m");}}
	if (!(ignoremask & IGNORE_C)) { if (STATEQ(st_ctime)) {FLAGIT("c");}}
	if (!(runtimeignore & IGNORE_0) && !(ignoremask & IGNORE_0))
					{ SIGEQ(0) {FLAGIT("0");}}
	if (!(runtimeignore & IGNORE_1) && !(ignoremask & IGNORE_1))
					{ SIGEQ(1) {FLAGIT("1");}}
	if (!(runtimeignore & IGNORE_2) && !(ignoremask & IGNORE_2))
					{ SIGEQ(2) {FLAGIT("2");}}
	if (!(runtimeignore & IGNORE_3) && !(ignoremask & IGNORE_3))
					{ SIGEQ(3) {FLAGIT("3");}}
	if (!(runtimeignore & IGNORE_4) && !(ignoremask & IGNORE_4))
					{ SIGEQ(4) {FLAGIT("4");}}
	if (!(runtimeignore & IGNORE_5) && !(ignoremask & IGNORE_5))
					{ SIGEQ(5) {FLAGIT("5");}}
	if (!(runtimeignore & IGNORE_6) && !(ignoremask & IGNORE_6))
					{ SIGEQ(6) {FLAGIT("6");}}
	if (!(runtimeignore & IGNORE_7) && !(ignoremask & IGNORE_7))
					{ SIGEQ(7) {FLAGIT("7");}}
	if (!(runtimeignore & IGNORE_8) && !(ignoremask & IGNORE_8))
					{ SIGEQ(8) {FLAGIT("8");}}
	if (!(runtimeignore & IGNORE_9) && !(ignoremask & IGNORE_9))
					{ SIGEQ(9) {FLAGIT("9");}}
	if (!reallychanged) {
	     list_setflag(p->varname, FLAG_UNCHANGE, &diff_changed_list);
	}

    }

    /* clean up */
    if (list_close(&diff_changed_list) < 0) {
	fprintf(stderr, "preen_report: list_close(diff_changed_list) failed!\n");
	exit(1);
    }

    return changed;
}

/*
 * structstat_fill(char *string, struct stat *statbuf, char *filename)
 *
 *	given a string from the database, fill in the statbuf structure.
 *	(filename) is provided for error reporting.
 *	
 *	return the ignore vector (a static system structure)
 */

static char *
structstat_fill (string, statbuf, sigs, recordkey)
    char *string;
    struct stat *statbuf;
    char sigs[NUM_SIGS][SIG_MAX_LEN];
    char *recordkey;
{
    char *ignorevec;
    static char structstat_fill_string[512];
    uint32        mode, ino, nlink, uid, gid, size;
    int entrynum;
    char vec64_a[50], vec64_m[50], vec64_c[50];

    (void) strcpy(structstat_fill_string, string);
    ignorevec = structstat_fill_string;

    if (sscanf(string, db_record_format,
		&entrynum, ignorevec,
		&mode, &ino, &nlink, &uid, &gid, &size,
		vec64_a, vec64_m, vec64_c,
		sigs[0], sigs[1], sigs[2], sigs[3], sigs[4],
		sigs[5], sigs[6], sigs[7], sigs[8], sigs[9])
				!= DB_RECORD_FIELDS) {
	fprintf(stderr, "structstat_fill: %s: illegal database record!  Aborting...\n", recordkey);
	fprintf(stderr, "	'%s'\n", string);
	exit(1);
    }
    statbuf->st_mode = (mode_t)mode;
    statbuf->st_ino = (ino_t)ino;
    statbuf->st_nlink = (nlink_t)nlink;
    statbuf->st_uid = (uid_t)uid;
    statbuf->st_gid = (gid_t)gid;
    statbuf->st_size = (off_t)size;

    /* convert from base64 to int */
    statbuf->st_atime = b64tol(vec64_a);
    statbuf->st_mtime = b64tol(vec64_m);
    statbuf->st_ctime = b64tol(vec64_c);

    return ignorevec;
}

/*
 * entrynum_get(char *string)
 *
 *	given a string from the database, return the entrynum
 */

static int
entrynum_get (string)
    char *string;
{
    char trash[1024];
    int entrynum;

    if (sscanf(string, "%d %s", &entrynum, trash) != 2) {
	fprintf(stderr, "entrynum_get: illegal database record!  Aborting...\n");
	fprintf(stderr, ">>	'%s'\n", string);
	exit(1);
    }

    return entrynum;
}

/*
 * pair_print_ss(char *label, char *s1, char *s2)
 *
 *	print {expected,received} table with strings
 */

static void
pair_print_ss (label, s1, s2)
    char *label;
    char *s1;
    char *s2;
{
    printf("%15s %-30s%-30s\n", label, s1, s2);
    return;
}

/*
 * pair_print_ll(char *label, int32 l1, int32 l2)
 *
 *	print {expected,received} table with int32s
 */

static void
pair_print_ll (label, l1, l2)
    char *label;
    int32 l1;
    int32 l2;
{
    printf("%15s %-30ld%-30ld\n", label, l1, l2);
    return;
}

/*
 * pair_print_llo(char *label, int32 l1, int32 l2)
 *
 *	print {expected,received} table with int32s in octal
 */

static void
pair_print_llo (label, l1, l2)
    char *label;
    int32 l1;
    int32 l2;
{
    printf("%15s %-30lo%-30lo\n", label, l1, l2);
    return;
}

static void
updateentry_list_add(filename)
    char *filename;
{
    char *pc;
    static int numinterupdated = 0;		

    pc = (char *) malloc((unsigned) strlen(filename) + 1);
    (void) strcpy(pc, filename);

    /* make sure we don't realloc() a null pointer */
    if (!pp_update) {
	if (!(pp_update = (char **) malloc(sizeof(char *))))
	    die_with_err("main: realloc() failed!\n", NULL);
    } 
    if ((pp_update = (char **) realloc(pp_update,
	    (numinterupdated+2) * sizeof(char *))) == NULL) {
	die_with_err("main: realloc() failed!\n", NULL);
    }
    pp_update[numinterupdated++] = pc;
    pp_update[numinterupdated] = NULL;
}

static void
updateentry_prompt(fttyin, fttyout, filename, entrynum, reset)
    FILE *fttyin, *fttyout;
    char *filename;
    int entrynum;
    int reset;
{
    static int firsttime = 1;
    static int lastanswer = 0;
    char answer[100], *pc;
    static int lastentrynum = -1;

    SPDEBUG(100) printf("updateentry_prompt: (entrynum=%d, lastentrynum=%d)\n",
    			entrynum, lastentrynum);

#define LASTANSWER_ALLYES 	1
#define LASTANSWER_ALLNO 	2
#define LASTANSWER_QUIT 	3

    if (reset) {
        firsttime = 1;
	lastanswer = 0;
	lastentrynum = -1;
    }

AGAIN:
    if (lastanswer == LASTANSWER_ALLNO) {
	if (entrynum == lastentrynum) {
	    return;
	}
	else {
	    lastentrynum = -1;
	    lastanswer = 0;
	}
    }
    if (lastanswer == LASTANSWER_ALLYES || test_interactive) {
	if (entrynum == lastentrynum) {
	    updateentry_list_add(filename); 
	    if (!test_interactive) {
		fprintf(fttyout, "---> Updating '%s'\n", filename_escape(filename));
		fflush(fttyout);
	    }
	    return;
	} 
	else {
	    lastentrynum = -1;
	    lastanswer = 0;
	}
    }

    if (!test_interactive) {
	fprintf(fttyout, "---> File: '%s'\n", filename_escape(filename));
	fprintf(fttyout, "---> Update entry?  [YN(y)nh?] ");
	fflush(fttyout);
	(void) fgets(answer, sizeof(answer), fttyin);
	pc = answer;
    } 
    /* we're in interactive testing mode */
    else {
	pc = "Y";
    }
    switch(*pc) {
    case '\n':
    case 'y': 	updateentry_list_add(filename); 
    		break;
    case 'Y': 	updateentry_list_add(filename); 
    		lastanswer = LASTANSWER_ALLYES;
		lastentrynum = entrynum;
		break;
    case 'n':	break;
    case 'N': 	lastanswer = LASTANSWER_ALLNO;
		lastentrynum = entrynum;
    		break;
    case 'h':   updateentry_help(fttyout);
    		goto AGAIN;
		break;
    case '?':	updateentry_menu(fttyout);
    		goto AGAIN;
    		break;
    default: 	fprintf(fttyout, 
		    "I don't understand your choice '%c'.  Try again.\n", 
		    *pc);
		goto AGAIN;
    }

    firsttime = 0;
}

static void
updateentry_menu(fpout)
    FILE *fpout;
{
    fprintf(fpout, "\n");
    fprintf(fpout, "	y:  Yes, update the database entry to match current file\n");
    fprintf(fpout, "	n:  No, leave database entry alone\n");
    fprintf(fpout, "	Y:  Yes, and change all other files in this entry\n");
    fprintf(fpout, "	N:  No, and leave all other entries alone\n");
    fprintf(fpout, "	h:  Print inode information help message\n");
    fprintf(fpout, "	?:  Print this help message\n");
    fprintf(fpout, "\n");
}

static void
updateentry_help(fpout)
    FILE *fpout;
{
    (void) tw_help_print(fpout);
}
