#ifndef lint
static char rcsid[] = "$Id: preen.c,v 1.29 1994/07/25 15:24:11 gkim Exp $";
#endif

/*
 * preen.c
 *
 *	preen the filesystems in preen.config against the data stored in
 *	in preen.database.
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
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#if (defined(SYSV) && (SYSV < 3))
# include <limits.h>
#endif	/* SVR2 */
#include <assert.h>
#include "../include/list.h"
#include "../include/tripwire.h"

static struct list *newdbase_list = NULL;
static int numentriesread = 0;		/* running count of @@contents */

/* prototypes */
char *mktemp();
static void olddbasefile_load();

char *updatemodes[] = {
	"invalid update",
	"add file",
	"delete file", 
	"update file",
	"entry not found",
	"add entry",
	"delete entry",
	"update entry",
};

/*
 * update_gather()
 *
 *	routine that calls all the other functions for preening
 *	in interactive mode.  (this is a wrapper around the functions
 *	of integrity checking mode and then update.)
 */

void
update_gather(interactive, ppp_updateentries)
    int interactive;
    char ***ppp_updateentries;
{
    FILE *fp_in;
    struct list *configentry_list = (struct list *) NULL;

    SPDEBUG(3) printf("*** entering update_gather()\n");

    /* build the filelist (newdbase_list) from the preen.config file
     * 		it will create the linked list of files
     */
    configfile_read(&newdbase_list, &configentry_list);

    /* if we're simply using as a preprocessor, then quit */
    if (printpreprocess)
	exit(0);

    /* preen ourselves:
     * 		build a temporary database, then check for diffs
     */
    database_build(&newdbase_list, DBASE_TEMPORARY, &configentry_list);

    /* read in the old database */
    olddbasefile_load(&configentry_list);
    assert(configentry_list);

    /* database_build() rewound the descriptor, so it's ready to use */
    fp_in = fptempdbase;

    /* build the diff_xxx_lists of ADDED, CHANGED, DELETED */
    preen_interp(fp_in);

    /* now build the report */
    preen_report(interactive, ppp_updateentries);
    if (!specified_configmode)
	(void) fclose(fp_in);

    /* remove the temporary database file */
    (void) unlink(tempdatabase_file);

    SPDEBUG(3) printf("*** leaving update_gather()\n");

    list_reset(&configentry_list);

    return;
}

/*
 * update_mark(char **ppentries, int numentries)
 *
 *	build the filelist (newdbase_list) from tw.config file.
 *	check if each (updateentry) in the (ppentries) vector is an entry
 *		if it is, update all entries with the same entrynum
 *		else if (updateentry) exists
 *			if so, update, w/same entrynum
 *			else append to database, w/entrynum = -1
 */

void
update_mark(ppentries, numentries)
    char **ppentries;
    int numentries;
{
    struct list *configentry_list = (struct list *) NULL;
    char *entry;
    int i, numskipped = 0;		/* number of entries not found */

    /* build the filelist (newdbase_list) from the tw.config file
     * 		it will create the linked list of files
     */

    list_reset(&newdbase_list);
    list_reset(&configentry_list);

    assert(!newdbase_list);
    assert(!configentry_list);
    assert(!olddbase_list);

    configfile_read(&newdbase_list, &configentry_list);

    /* read in the old database */
    olddbasefile_load(&configentry_list);

SPDEBUG(20) {
printf("===== configentry_list ===\n");
list_print(&configentry_list);
printf("===== newdbase_list ===\n");
list_print(&newdbase_list);
printf("===== olddbase_list ===\n");
list_print(&olddbase_list);
}


    /* iterate through the entries */
    for (i = 0; i < numentries; i++) {

	int isentry, isold, isnew;
	int whichcase;

	entry = ppentries[i];
    	/* check to see if filename is fully-qualified! */
	if (entry[0] != '/') {
	    fprintf(stderr, 
"%s: file '%s' is not fully qualified!  Skipping...\n", progname, entry);
	    numskipped++;
	    continue;
	}

	/*
	 *			tw.config	old dbase	new dbase
	 *			=========	========	========
	 *		0.	-		-		-
	 *		1.	-		-		y
	 *		2.	-		y		-
	 *		3.	-		y		y
	 *		4.	y		-		-
	 *		5.	y		-		y
	 *		6.	y		y		-
	 *		7.	y		y		y
	 *
	 *
	 *	(0) xxx -- can't happen
	 *		skip, invalid filename
	 *
	 *	(1) add file -- adds the single file to the database
	 *	(what contents number do we give it?  what ignore flags?)
	 *
	 *	(2) delete file -- removes the single file from the database.
	 *
	 *	(3) update file -- updates the single file in the database.
	 *		(inherit new ignore mask)
	 *
	 *	(4) xxx -- the entry doesn't resolve to any files on the system.
	 *		(no change)
	 *
	 *	(5) add entry -- recurses down the specified entry and adds all
	 *		the resulting files to the database.
	 *		(ignore mask comes from "closest" tw.config entry)
	 *
	 *	(6) delete entry -- the files disappeared since the last 
	 *		dbase snapshot so, delete the entire entry
	 *
	 *	(7) update entry -- recurses down the specified entry and 
	 *		updates all those entries in the database
	 *		(inherit new ignore mask)
    	 */

	isentry = list_isthere(entry, &configentry_list);
	isnew = list_isthere(entry, &newdbase_list);
	isold = list_isthere(entry, &olddbase_list);

	/* our case number is the vector of true/false bits */
	whichcase = (isentry << 2) | (isold << 1) | (isnew);
	if (!quietmode) { 
	    fprintf(stderr, "Updating: %s: %s\n", updatemodes[whichcase], 
		    filename_escape(entry));
	}

	switch(whichcase) {
	case UPDATE_INVALID:
	case UPDATE_NOTFOUND:
	    if (!quietmode) {
	    fprintf(stderr, "update: %s: invalid entry!  skipping...\n",
				entry);
	    }
	    continue;
	case UPDATE_ADDFILE:
	{
	    char entry_ignorevec[64]; 
	    char ignorestring[64];
	    char *pc;
	    int entrynum;
	    char entryname[1024];

	    if (verbosity)
		fprintf(stderr, "Adding file %s\n", filename_escape(entry));

	    dbase_entry_howclose(entry, &configentry_list, entryname, 
		&entrynum);

	    /* we use the default ignore-string.  XXX.  Must be definable */
	    if (!(pc = list_lookup(entry, &newdbase_list))) {
		strcpy(ignorestring, defaultignore);
		ignore_configvec_to_dvec(ignorestring);
	    } else {
		char tmpignore[64];
		int j, err;

		if ((err = sscanf(pc, "%d %s", &j, tmpignore)) != 2) {
		fprintf(stderr, "update_mark: newdbase_list parse error (nfields=%d, %s:%d)!\n", err, __FILE__, __LINE__);
		    fprintf(stderr, "%s>> %s\n", entry, pc);
		    exit(1);
		}

		strcpy(ignorestring, tmpignore);
	    }

	    sprintf(entry_ignorevec, "%d %s", entrynum, ignorestring);
	    list_set(entry, entry_ignorevec, MAXPATHLEN+1, &olddbase_list);
	    list_setflag(entry, FLAG_UPDATE, &olddbase_list);

	}
	    break;
	case UPDATE_DELETEFILE:
	    if (verbosity)
		fprintf(stderr, "Deleting file %s\n", filename_escape(entry));
	    list_unset(entry, &olddbase_list);
	    break;
	case UPDATE_UPDATEFILE:
	{
	    char oldignore[64], newignore[64], *pc, 
			oldrest[1024];
	    char newvalue[1024];
	    int err, newentry, oldentry;

	    if (verbosity)
		fprintf(stderr, "Updating file %s\n", filename_escape(entry));

	    /* we know that the entry exists the the new dbaselist, otherwise,
	     * we couldn't be in this case!
	     */

	    pc = list_lookup(entry, &newdbase_list);
	    assert(pc != NULL);

	    /* parse the new dbase entry */
	    if ((err = sscanf(pc, "%d %s", &newentry, newignore)) != 2) {
		fprintf(stderr, "update_mark: newdbase_list parse error (nfields=%d, %s:%d)!\n", err, __FILE__, __LINE__);
		fprintf(stderr, "%s>> %s\n", entry, pc);
		exit(1);
	    }

	    /* parse the old dbase entry */
	    pc = list_lookup(entry, &olddbase_list);
	    assert(pc != NULL);

	    /* parse the old dbase entry */
	    if ((err = sscanf(pc, "%d %s %[^\n]", &oldentry, oldignore, 
			oldrest)) != 3) {
		if (list_getflag(entry, &olddbase_list) & 
				    FLAG_UPDATE) {
		    SPDEBUG(3) printf("\t(it's already a newly file...)\n");
		    break;
		}
		fprintf(stderr, "update_mark: olddbase_list parse error (nfields=%d, %s:%d)!\n", err, __FILE__, __LINE__);
		fprintf(stderr, "%s>> %s\n", entry, pc);
		exit(1);
	    }

	    /* splice the new ignore flag into the old dbase list */
	    sprintf(newvalue, "%d %s %s\n", oldentry, newignore, oldrest);

	    /* check to make sure we're not overflowing bounds */
	    /*	why?  the ignore mask is the only thing that changed,
	     * 	so the length of the entire string should also remain
	     * 	unchanged.
	     */
	    assert(strlen(newvalue) == strlen(pc));

	    list_set(entry, newvalue, MAXPATHLEN+1, &olddbase_list);
	    list_setflag(entry, FLAG_UPDATE, &olddbase_list);
	}
	    break;
	case UPDATE_ADDENTRY:
	{
	    struct list_elem *p;
	    char ignorevec[128];
	    int number;
	    char *pc;
	    int err;

	    if (verbosity)
		fprintf(stderr, "Adding entry %s\n", filename_escape(entry));

	    if (!(pc = list_lookup(entry, &configentry_list))) {
		fprintf(stderr, "%s: Can't find entry '%s'.  Skipping...\n",
			progname, entry);
		continue;
	    }
	    if ((err = sscanf(pc, "%d %s", &number, ignorevec)) != 2) {
		fprintf(stderr, "update_mark: configentry_list parse error (nfields=%d, %s:%d)!\n", err, __FILE__, __LINE__);
		    fprintf(stderr, "%s>> %s\n", entry, pc);
		    exit(1);
	    }

	    list_open(&newdbase_list);
	    while ((p = list_get(&newdbase_list))) {
		int thisentry;

		if (sscanf(p->varvalue, "%d", &thisentry) != 1) {
		    fprintf(stderr, "update_mark: newdbase_list parse error (nfields=%d, %s:%d)!\n", err, __FILE__, __LINE__);
		    fprintf(stderr, "%s>> %s\n", p->varname, p->varvalue);
		    exit(1);
		}
		/* does it match the entry we're adding? */
		if (thisentry == number) {
		    SPDEBUG(6) { printf("--(adding entry)--> %s\n", 
			p->varname); }
		    list_set(p->varname, p->varvalue, MAXPATHLEN+1, &olddbase_list);
		    list_setflag(p->varname, FLAG_UPDATE, &olddbase_list);
		}
	    }
	    list_close(&olddbase_list);
	}
	    break;
	case UPDATE_DELETEENTRY:
	case UPDATE_UPDATEENTRY:
	    if (verbosity) {
		switch(whichcase) {
		case UPDATE_DELETEENTRY:
		    fprintf(stderr, "Deleting entry %s\n", filename_escape(entry));
		    break;
		case UPDATE_UPDATEENTRY:
		    fprintf(stderr, "Updating entry %s\n", filename_escape(entry));
		break;
		}
	    }
	{
	    struct list_elem *p, *q = (struct list_elem *) NULL;
	    char s[2048];
	    int entrynum;
	    char newignore[1024];
	    int err;

	    /* get entry number and new ignore mask */
	    (void) strcpy(s, list_lookup(entry, &configentry_list));
	    if ((err = sscanf(s, "%d %s", &entrynum, newignore)) != 2) {
		fprintf(stderr, "update_mark: configentry_list parse error (nfields=%d, %s:%d)!\n", err, __FILE__, __LINE__);
		fprintf(stderr, "%s>> %s\n", entry, s);
		exit(1);
	    }

	    /* we're updating entries */
	    if (whichcase == UPDATE_UPDATEENTRY) {
		dbase_entry_flag(&olddbase_list, entrynum, FLAG_UPDATE, 
			(char *) newignore);
	    }
	    /* else we're deleting entries */
	    else {
		dbase_entry_flag(&olddbase_list, entrynum, FLAG_DELETE, NULL);
		SPDEBUG(20) list_print(&olddbase_list);

		list_open(&olddbase_list);
		while ((p = list_get(&olddbase_list))) {
		    if (q) {
			list_unset(q->varname, &olddbase_list);
			q = (struct list_elem *) NULL;
		    }
		    if (list_getflag(p->varname, &olddbase_list)
					& FLAG_DELETE) {
			q = p;
		    }
		}
		if (q) {
		    list_unset(q->varname, &olddbase_list);
		    q = (struct list_elem *) NULL;
		}
		    
		list_close(&olddbase_list);
		list_unset(entry, &configentry_list);
		SPDEBUG(20) { list_print(&configentry_list); }
	    }
	}
	    break;
	default:
	    fprintf(stderr, "update_mark: invalid case %d!\n", whichcase);
	    exit(1);
	}

    }
    
    /* did we skip all the files, thus a no-op? */
    if (numskipped == numentries) {
        printf("%s: No updated entries.  Database remains unchanged.\n",
			progname);
	exit(1);
    }

    /* we used to print the backup warning banner here -- now it's in 
     * dbase.build.c 
     */

    /* preen ourselves:
     * 		build a temporary database, then check for diffs
     */
    database_build(&olddbase_list, DBASE_UPDATE, &configentry_list);

    return;
}

/*
 * void
 * olddbasefile_load(ppentrylist)
 *
 *	load in the old database file into the global list (olddbase_list).
 *	(ppentrylist) is the list of entries.
 */

static void
olddbasefile_load(ppentrylist)
    struct list **ppentrylist;
{
    char filename[MAXPATHLEN+256];
    FILE *fp;
    char s[MAXPATHLEN+512];
    char key[MAXPATHLEN+256], value[512];
    static struct list *replace_list = (struct list *) NULL;

    SPDEBUG(3) printf("*** entering olddbasefile_load()\n");

    if (specified_dbasemode == SPECIFIED_FILE)
	(void) strcpy(filename, specified_dbasefile);
    else
	sprintf(filename, "%s/%s", database_path, database_file);

    /* did we specify a dbase file? */
    if (specified_dbasemode) {
        if (!(fp = (FILE *) fdopen(specified_dbasefd, "r"))) {
	    die_with_err("Couldn't open database file '%s'",
			    filename);
	}
	rewind(fp);
	if (ftell(fp) != 0) {
	    die_with_err("olddbasefile_load: ftell()", NULL);
	}
    }
    /* else open the file */
    else {
	if ((fp = fopen(filename, "r")) == NULL)
	    die_with_err("Couldn't open database file '%s'",
			    filename);
    }

    /* first make sure that none of the entry numbers changed */
    while (fgets(s, sizeof(s), fp) != NULL) {
	char entryname[2048], *pc;
	int oldentrynum, newentrynum;
	static int countlines;

	countlines++;
	if (string_split_space(s, key, value) < 0) {
	    fprintf(stderr, 
		"%s: database='%s': parse error: space not found in line %d!\n",
		progname, filename, countlines);
	    exit(1);
	}

	/* build table of contents */
	if (strcmp(key, "@@contents") != 0) {
	    continue;
	}

	/* check to see if entrynums match */
	if (sscanf(value, "%s %d", entryname, &oldentrynum) != 2) {
	    fprintf(stderr, 
		"olddbasefile_load: parse error at %s: %d\n>>%s", __FILE__,
		__LINE__, s);
	    exit(1);
	}
	filename_escape_expand(entryname);
	if (!list_isthere(entryname, ppentrylist))
	    continue;
	pc = list_lookup(entryname, ppentrylist);
	newentrynum = atoi(pc);

	/* if discrepency, then store in replace_list */
	if (oldentrynum != newentrynum) {
	    char oldent[100], newent[100];
	    /* gotta do some chopping up of the contents information */
	    sprintf(oldent, "%d", oldentrynum);
	    sprintf(newent, "%d", newentrynum);
	    list_set(oldent, newent, MAXPATHLEN+1, &replace_list);
	}
    }

    rewind(fp);

    /* read in entire file */
    while (fgets(s, sizeof(s), fp) != NULL) {
    	static int countlines = 0;

	countlines++;

	/* skip comments */
	if (s[0] == '#')
	    continue;
	
	if (string_split_space(s, key, value) < 0) {
	    fprintf(stderr, 
		"%s: database='%s': parse error: space not found in line %d!\n",
		progname, filename, countlines);
	    exit(1);
	}

	/* build table of contents */
	if (strcmp(key, "@@contents") == 0) {
	    numentriesread++;
	    continue;
	}
	/* skip database version */
	else if (strcmp(key, "@@dbaseversion") == 0) {
	    int version, err;
	    if ((err = sscanf(value, "%d", &version)) != 1) {
		fprintf(stderr, "olddbasefile_load: @@dbaseversion parse error (nfields=%d, %s:%d)!\n", err, __FILE__, __LINE__);
		    fprintf(stderr, ">> %s\n", key);
		    exit(1);
	    }

	    if (version != DB_VERSION_NUM) {
		/* special case */
		if (DB_VERSION_NUM == 4 && version == 3) {
		    fprintf(stderr,
"%s: %s: version mismatch\n", progname, filename);
		    fprintf(stderr,
"\tdatabase format %d is no longer fully supported (expecting %d)!\n",
			    version, db_version_num);
		    fprintf(stderr,
"\tSee tw.config(5) manual page for details\n");
		}
		else {
		    fprintf(stderr,
"%s: %s: version error\n", progname, filename);
		    fprintf(stderr,
"\tdatabase format %d is no longer supported (expecting %d)!\n",
			    version, db_version_num);
		    fprintf(stderr,
"\tSee tw.config(5) manual page for details\n");
		    exit(1);
		}
	    }
	    continue;
	}
	/* else it's a file */
	else {
	    int mode;
	    char pcentry[512], pcignore[512], pcrest[1024];
	    char newvalue[1024];
	    int err;

SPDEBUG(10)
printf("olddbasefile_load: %s: %s", key, value);

	    filename_escape_expand(key);

	    /* check to see if it's a special file */
	    if ((err = sscanf(value, "%s %s %o %[^\n]", pcentry, pcignore, &mode,
			pcrest)) != 4) {
		fprintf(stderr, "olddbasefile_load: parse error (nfields=%d)!", 
				err);
		fprintf(stderr, ">> %s", value);
		exit(1);
	    }

	    /* do we need to replace the entry number? */
	    if (list_isthere(pcentry, &replace_list)) {
		/* splice the new value in */
		sprintf(newvalue, "%s %s %o %s\n", 
		    list_lookup(pcentry, &replace_list), 
		    pcignore, mode, pcrest);
		list_set(key, newvalue, MAXPATHLEN+1, &olddbase_list);
	    }
	    /* otherwise the entry number was fine */
	    else {
		list_set(key, value, MAXPATHLEN+1, &olddbase_list);
	    }

	    switch (mode & S_IFMT) {
	      case S_IFIFO:
	      case S_IFCHR:
	      case S_IFDIR:
	      case S_IFBLK:
#if !defined(SYSV) || (SYSV > 3)
#ifndef apollo
/* Foolish Apollos define S_IFSOCK same as S_IFIFO in /bsd4.3/usr/include/sys/stat.h */
	      case S_IFSOCK:
#endif
#endif
		(void) list_setflag(key, FLAG_NOOPEN, &olddbase_list);
		break;
#if !defined(SYSV) || (SYSV > 3)
	      case S_IFLNK:	/* if it's a symbolic link, make sure we flag it as such! */
		(void) list_setflag(key, FLAG_SYMLINK, &olddbase_list);
		break;
#endif
	    }

	}
    }

    /* close the file descriptor */
    if (!specified_dbasemode)
	(void) fclose(fp);

    SPDEBUG(3) printf("*** leaving olddbasefile_load()\n");

    list_reset(&replace_list);

    return;
}

/*
 * dbase_entry_closest()
 *
 * 	given a (filename), choose the "closest" entry in the tw.config
 *	file.
 *
 *		Ex: 	filename = "/etc/foo/bar"
 *
 *		entry:		score:
 *		/etc		1
 *		/etc/foo	2
 *		/etc/foo/bar	3
 *
 */

void
dbase_entry_howclose(filename, ppentrylist, entry, pentrynum)
    char *filename;
    struct list **ppentrylist;
    char *entry;
    int *pentrynum;
{
    struct list_elem *p;
    int maxscore = 0;

    if (list_open(ppentrylist) < 0) {
	fprintf(stderr, "%s: dbase_entry_howclose: list_open() failed!\n",
		progname);
	exit(1);
    }

    while ((p = list_get(ppentrylist))) {
	char *p1, *p2;
	int score = 0;
	char trash[1024];
	int entrynum = 0;
	char *pold;

	p1 = p->varname;
	p2 = filename;

	/* walk through the filenames */
	for (; *p1 && *p2; p1++, p2++) {
	    if (*p1 != *p2)
		break;
	    if (*p2 == '/')		/* increment score */
		score++;
	}
	/* correct score if comparison failed */
	if ((p1 != p->varname) && *(p1-1) == '/')
	    score--;

SPDEBUG(6) 
printf("dbase_entry_howclose: %d: (%s,%s)\n", score, filename, p->varname);

	if (score > maxscore) {
	    maxscore = score;
	    strcpy(entry, p->varname);
	    /* grab the entry number */
	    if ((pold = list_lookup(p->varname, &olddbase_list))) {
		if (sscanf(pold, "%d %s", &entrynum, trash) != 2) {
		   die_with_err("dbase_entry_howclose: sscanf() parsing error!\n",
							(char *) NULL);
		}
	    }
	    *pentrynum = entrynum;
	}
    }

    if (list_close(ppentrylist) < 0) {
	fprintf(stderr, "%s: dbase_entry_howclose: list_close() failed!\n",
		progname);
	exit(1);
    }

SPDEBUG(6) 
printf("dbase_entry_howclose: ancestor: %s\n", entry);

}

