#ifndef lint
static char rcsid[] = "$Id: utils.c,v 1.23 1994/07/25 16:23:16 gkim Exp $";
#endif

/*
 * utils.c
 *
 *	miscellaneous utilities for Tripwire
 *
 * Gene Kim
 * Purdue University
 */

#include "../include/config.h"
#include "../include/byteorder.h"
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#if !defined(SYSV) || (SYSV > 3)
# include <sys/file.h>
#else
# include <unistd.h>
#endif 	/* SYSV */
#ifdef STDLIBH
#include <stdlib.h>
#include <unistd.h>
#endif
#include <ctype.h>
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
# if (!defined(strchr) && !defined(index))
#  define strchr(s, c) index(s, c)
# endif
# if (!defined(memcpy) && !defined(bcopy))
#  define memcpy(to, from, n) bcopy(from, to, n)
# endif
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <sys/param.h>
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif
#ifndef XENIX
# include <sys/time.h>
#else
# include <time.h>
#endif 	/* XENIX */
#ifndef GETHOSTNAME
# include <sys/utsname.h>
#endif
#if (defined(SYSV) && (SYSV < 3))
# include <limits.h>
#endif	/* SVR2 */
#include "../include/list.h"
#include "../include/tripwire.h"

#ifndef SEEK_SET
# define SEEK_SET L_SET
#endif

#ifndef L_tmpnam
# define L_tmpnam (unsigned int) MAXPATHLEN
#endif

static void print_perm();

#ifndef S_IRGRP
#define S_IRGRP	(S_IREAD >> 3)
#define S_IWGRP (S_IWRITE >> 3)
#define S_IXGRP (S_IEXEC >> 3)
#define S_IROTH (S_IREAD >> 6)
#define S_IWOTH (S_IWRITE >> 6)
#define S_IXOTH (S_IEXEC >> 6)
#endif

void warn_with_err(format, name)
   char *format, *name;
{
    extern int  errno;
    int real_errno = errno;
    char *string;

    if (!name)
      string = format;
    else {
	string = (char *) malloc((unsigned) (strlen(format)+strlen(name)+1));
	if (!string) {
	    fputs("Unexpected malloc() failure in 'warn_with_err'!\n", stderr);
	    exit(-1);
	}
	sprintf(string, format, name);
	errno = real_errno;
    }

    perror(string);
}

void
die_with_err(format, name)
    char *format, *name;
{
    warn_with_err(format, name);
    exit(1);
}

/*
 * filename_hostname_expand(char **ps)
 *
 *	expand any '@'s in the specified string to the hostname.
 *
 *	Ex:   "xxx_@_xxx"  ---> "xxx_mentor.cc.purdue.edu_xxx"
 */

static char hostname[MAXHOSTNAMELEN];

void
filename_hostname_expand(ps)
    char **ps;
{
    char *s = *ps;
    char outpath[MAXPATHLEN+256];
    char *pc;

    if (! *hostname) {   /* we only need to do this once */
#ifndef GETHOSTNAME
    struct utsname sysinfo;

    if (uname(&sysinfo) < 0)
	die_with_err("filename_hostname_expand: uname()", (char *) NULL);

    (void) strcpy(hostname, sysinfo.nodename);

#else 	/* GETHOSTNAME */

    /* get the hostname */
    if (gethostname(hostname, sizeof(hostname)) < 0)
	die_with_err("filename_hostname_expand: gethostname()", (char *) NULL);

#endif 	/* GETHOSTNAME */
    }

    /* is there a '@' in the filename? */
    if ((pc = strchr(s, '@')) == NULL) {
	return;
    }

    /* copy the first part of the string */
    (void) strncpy(outpath, s, pc-s);

    /* strncpy() doesn't guarantee null-terminated strings! */
    outpath[pc-s] = '\0';

    /* expand the '@' and copy the rest of the string */
    (void) strcat(outpath, hostname);
    (void) strcat(outpath, pc+1);

    /* make our pointer point to the expanded string */
    if ((pc = (char *) malloc((unsigned int) (strlen(outpath) + 1))) == NULL)
	die_with_err("filename_hostname_expand: malloc()", (char *) NULL);

    (void) strcpy(pc, outpath);

    *ps = pc;

    return;
}

/*
 * slash_count(char *pathname)
 *
 *	count the number of slashes in a given pathname.  This is used
 * 	to determine the priority of a given file entry when generating
 * 	the list of files.
 */

int
slash_count (pathname)
    char *pathname;
{
	register int count = 0;
	register char *pc;

	for (pc = pathname; *pc; pc++ )
		if (*pc == '/')
			count++;
	return count;
}

/*
 * string_split_space(char *string, char *s, char *t)
 *
 * 	given (string), place the first word into (s), and the rest of
 *	into (t).
 *
 *	returns zero on success, -1 on failure.
 */

int
string_split_space (string, s, t)
    char *string;
    char *s;
    char *t;
{
    char *sp;

    /*
     * (char *sp) = the first space.  	s = {string[0..(sp-s-1)]}
     *			      		t = {sp[1..end]}
     */

    if ((sp = strchr(string, ' ')) == NULL) {
SPDEBUG(10) 
fprintf(stderr, "string_split_space: string doesn't contain space!\n");
	return -1;
    }

    /* don't forget to null-terminate the string w/strncpy() */
    (void) strncpy(s, string, sp-string);
    s[sp-string] = '\0';

    (void) strcpy(t, sp+1);
    return 0;
}

/*
 * int
 * string_split_ch(char *string, char *s, char *t, char ch)
 *
 * 	given (string), place the first word into (s), and the rest of
 *	into (t), using (ch) as the field separator.  (ala perl).
 */

int
string_split_ch (string, s, t, ch)
    char *string;
    char *s;
    char *t;
    int ch;
{
    char *sp;

    /*
     * (char *sp) = the first space.  	s = {string[0..(sp-s-1)]}
     *			      		t = {sp[1..end]}
     */

    if ((sp = strchr(string, ch)) == NULL) {
	(void) strcpy(s, string);
	t[0] = '\0';
	return -1;
    }

    /* don't forget to null-terminate the string w/strncpy() */
    (void) strncpy(s, string, sp-string);
    s[sp-string] = '\0';

    (void) strcpy(t, sp+1);
    return 0;
}

/*
 * chop (char *s)
 *
 *	chop off the last character in a string, ala Perl.
 */

void
chop (s)
    char *s;
{
	int slen;

	slen = strlen(s);
	s[slen-1] = '\0';
	return;
}

/*
 * filename_escape_expand(char *filename)
 *
 *	expand \xxx octal characters, metachacters, and known
 *	C escape sequences.
 */

void
filename_escape_expand (filename)
    char *filename;
{
    int i = 0;
    static char filetmp[MAXPATHLEN+256];
    int octal;
    register char *pcin = filename, *pcout = filetmp;

    /*
     * case I:	it's not escaped
     * case II: 	it's a three digit octal number
     * case III:	it's a standard C escape sequence
     *				(\n, \r, \', \", \t, \b, \f)
     *			(from Johnson, Stephen C.,
     *				"Yacc: Yet Another Compiler-Compiler")
     * case IV:	it's one of our metacharacters {@#!|&()= }
     */

    while (*pcin) {

	/* case I: it's not an escape */
	if (*pcin != '\\') {
		*pcout++ = *pcin++;
	}

	/* case II: it's a three digit octal number */
	else if (isdigit(*++pcin)) {
	    /* read in the three characters */
	    for (octal = i = 0; i < 3 ; i++, pcin++) {
		octal *= 8;
		
		if (*pcin > '7' || *pcin < '0') {
		    fprintf(stderr,
			    "filename_escape_expand: bogus octal character (%c) in file `%s'!\n",
			    *pcin, filename);
		    exit(1);
		}
		else
		  octal += *pcin-'0';
	    }

	    /* warn of filenames with null's in them */
	    if (octal == 0) {
		fprintf(stderr, "tripwire: warning: null character in file `%s'!\n",  filename);
		exit(1);
	    }

	    *pcout++ = octal & 0xff;
	}

	/* case III: it's a standard C escape sequence */
	/* case IV: it's one of our escape characters */
	else
	    switch(*pcin) {
	    case 'n':		{ *pcout++ = '\n'; break; }
	    case 'r':		{ *pcout++ = '\r'; break; }
	    case 't':		{ *pcout++ = '\t'; break; }
	    case 'b':		{ *pcout++ = '\b'; break; }
	    case 'f':		{ *pcout++ = '\f'; break; }
	    case '\'':		
	    case '"':		
	    case '@':
	    case '!':
	    case '#':
	    case '=':
	    case ' ':
	    case ')':
	    case '(':
	    case '&':
	    case '|':
	    case '\\':
	      /* same as our default case... it's the character itself */
	    default: 		{ *pcout++ = *pcin++; break; }
	  }
    }


    /* null terminate the string */
    *pcout++ = '\0';

    (void) memcpy(filename, filetmp, pcout - filetmp);
    return;
}

/*
 * char *
 * filename_escape(char *filename)
 *
 *	find any characters that must be escaped in the file name.
 */

char *
filename_escape (filename)
    char *filename;
{
    static char filetmp[MAXPATHLEN+256];
    register char *pcin = filename, *pcout = filetmp;
    static char *octal_array[] = {
	"000", "001", "002", "003", "004", "005", "006", "007",
	"010", "011", "012", "013", "014", "015", "016", "017",
	"020", "021", "022", "023", "024", "025", "026", "027",
	"030", "031", "032", "033", "034", "035", "036", "037",
	"040", "041", "042", "043", "044", "045", "046", "047",
	"050", "051", "052", "053", "054", "055", "056", "057",
	"060", "061", "062", "063", "064", "065", "066", "067",
	"070", "071", "072", "073", "074", "075", "076", "077",
	"100", "101", "102", "103", "104", "105", "106", "107",
	"110", "111", "112", "113", "114", "115", "116", "117",
	"120", "121", "122", "123", "124", "125", "126", "127",
	"130", "131", "132", "133", "134", "135", "136", "137",
	"140", "141", "142", "143", "144", "145", "146", "147",
	"150", "151", "152", "153", "154", "155", "156", "157",
	"160", "161", "162", "163", "164", "165", "166", "167",
	"170", "171", "172", "173", "174", "175", "176", "177",
    };
    register char *pccopy;

    /* these only matter if they are the first character */
    if (*pcin == '!' || *pcin == '=' || *pcin == '#')	
	{ *pcout++ = '\\'; *pcout++ = *pcin++; }

    /* these must be replace everywhere in the filename */
    while (*pcin) {
	if (isalnum(*pcin)) {
	    *pcout++ = *pcin;
	}
	else if (iscntrl(*pcin)) {
	    *pcout++ = '\\';
	    *pcout++ = *(pccopy = octal_array[(int)(*pcin)]);
	    *pcout++ = *++pccopy;
	    *pcout++ = *++pccopy;
	} 
	else {
	    switch(*pcin) {
	      case '\\':
	      case '\'':
	      case '\"':
	      case '@':
	      case ' ':
	      case '(':
	      case ')':
	      case '&':
	      case '|':
	      case '#':
		*pcout++ = '\\';
		*pcout++ = *(pccopy = octal_array[(int)(*pcin)]);
		*pcout++ = *++pccopy;
		*pcout++ = *++pccopy;
		break;
	    default:
		*pcout++ = *pcin;
		break;
	    }
	}
	pcin++;
    }

    /* null terminate the string */
    *pcout++ = '\0';

    return filetmp;
}

#define NEWBASE64
#ifdef NEWBASE64
static char base64vec[] =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:.";
#else
static char base64vec[] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
#endif

/* pltob64 -- walk through a vector of int32s, convert them to 
 *	network byte ordering, and then convert to base 64
 *
 *	this is the preferred interface to btob64.
 */

#define NUMTMPLONGS	1000
char *
pltob64(pl, pcout, numlongs)
    uint32 *pl;
    char *pcout;
    int numlongs;
{
    register int i;
    register uint32 *plto;
    uint32 larray[NUMTMPLONGS];

    assert(numlongs < NUMTMPLONGS);
    /* we use our own ntohl() routines, but we have to do it in-place */
    memcpy((char *) larray, (char *) pl, numlongs*sizeof(uint32));

    for (i = 0, plto = larray; i < numlongs; i++) {
	bs_htonl(*plto++);
    }

    return btob64((unsigned char *) larray, (char *) pcout, numlongs*sizeof(uint32)*8);
}

/* btob64  -- convert arbitrary bits to base 64 string
 *
 * Input: bit array (represented as u_char array)
 *        number of bits in the array
 *        ptr-to-str for return string val
 *
 *  This is high magic.  Trust me.  --spaf
 */


char *
btob64(pcbitvec, pcout, numbits)
    register unsigned char *pcbitvec;
    register char  *pcout;
    int numbits;
{
    register unsigned int val;
    register int offset;
    unsigned char *pcorig = (unsigned char *) pcout;

    assert(sizeof(unsigned char) == 1);	/* everything breaks otherwise */
    assert(numbits > 0);

    val = *pcbitvec;

    offset = numbits % 6;   /* how many bits initially? */
    if (offset) 
    {
	val >>= (8 - offset);
	*pcout++ = base64vec[val & 0x1f];
    }

    for ( numbits -= offset; numbits > 0; offset += 6, numbits -= 6)
    {
	val = *pcbitvec;
	if (offset > 2) 
	{
	    offset -= 8;
	    val <<= 8;
	    val |= *++pcbitvec;
	}
	val >>= (2-offset);

	*pcout++ =  base64vec[val & 0x3f];
    }

    *pcout = '\0';

    return (char *) pcorig;
}

#ifdef FOO
char *
ltob64(num, vec64)
    register uint32 num;
    char *vec64;
{
    register char *p1 = vec64;
    register int i;


    /* build lsb -> msb */
    for (i = 5; i >= 0; i--) {
        p1[i] = base64vec[num & 0x3f];
	num >>= 6;
    }

    vec64[6] = 0;

    return vec64;
}
#endif

/*
 * int32
 * b64toi(char *vec)
 *
 *	given a base-64 string, convert to a int32.
 */

int32
b64tol(vec)
    char *vec;
{
    register char *pc;
    register int32 num = 0L;

/* we use a different base-64 vector now to preseve zero's traditional
 * value.
 */

#ifdef NEWBASE64
    for (pc = vec; *pc; pc++) {
	num <<= 6;
	
	/* 0 - 9 */
	if (*pc >= '0' && *pc <= '9')
	  num += (*pc - '0');		/* 0..9 = '0' .. '0' */
	else if (*pc >= 'A' && *pc <= 'Z')
	  num += (*pc - 'A' + 10);	/* 10..35 = '65-55' .. '90-55' */
	else if (*pc >= 'a' && *pc <= 'z')
	  num += (*pc - 'a' + 36);	/* 36..61 = '97-35' .. '122-61' */
	else if (*pc == ':')
	  num += 62;
	else if (*pc == '.')
	  num += 63;
	else {
	  fprintf(stderr, "b64tol: fatal error: unknown character '%c'.\n",
		*pc);
	  exit(1);
	}
    }

    return num;
#else
    for (pc = vec; *pc; pc++) {
	num <<= 6;
	
	num += *pc;
	if (*pc <= '9') 	
	  num -= '.';
	else if (*pc <= 'Z')
	  num -= '5';  /* '5' == 'A' - 12 */
	else
	  num -= ';';  /* ';' == 'a' - 38 */
    }

    return num;
#endif
}

int32
oldb64tol(vec)
    char *vec;
{
    register char *pc;
    register int32 num = 0L;

    for (pc = vec; *pc; pc++) {
	num <<= 6;
	
	num += *pc;
	if (*pc <= '9') 	
	  num -= '.';
	else if (*pc <= 'Z')
	  num -= '5';  /* '5' == 'A' - 12 */
	else
	  num -= ';';  /* ';' == 'a' - 38 */
    }

    return num;
}

/*
 * direntry_print(char *name, struct stat stabuf))
 *
 *	print out a pretty directory entry for the specified file
 *
 *	this routine was taken from crc_check.c, written by Jon Zeeff
 *	(zeeff@b-tech.ann-arbor.mi.us)
 *
 *	hacked for use in Tripwire by Gene Kim.
 */

void
direntry_print (name, statbuf, mode)
    char *name;
    struct stat statbuf;
    int mode;
{
	struct passwd *entry;
	static char owner[20];
	char    a_time[50];

	static int prev_uid = -9999;

	switch(mode) {
	case DIFF_ADDED:
		printf("added:   "); break;
	case DIFF_CHANGED:
		printf("changed: "); break;
	case DIFF_DELETED:
		printf("deleted: "); break;
	}

	if (statbuf.st_uid != prev_uid) {
		entry = (struct passwd *)getpwuid((int) statbuf.st_uid);
		if (entry)
			(void) strcpy(owner, entry->pw_name);
		else
			(void) sprintf(owner, "%d", statbuf.st_uid);
		prev_uid = statbuf.st_uid;
	}
	/*
	if (statbuf.st_gid != prev_gid) {
		group_entry = getgrgid((int) statbuf.st_gid);
		if (group_entry)
			(void) strcpy(group, group_entry->gr_name);
		else
			(void) sprintf(group, "%d", statbuf.st_gid);
		prev_gid = statbuf.st_gid;
	}
	*/

	(void) strcpy(a_time, ctime(&statbuf.st_mtime));
	a_time[24] = '\0';

	print_perm((uint32)statbuf.st_mode);

	(void) printf(" %-9.9s %7d %s", owner, statbuf.st_size,
						a_time + 4);
	printf(" %s\n", name);

}

/*	
 *	This routine was taken from crc_check.c, written by Jon Zeeff
 *	(zeeff@b-tech.ann-arbor.mi.us)
 *
 *	hacked for use in Tripwire by Gene Kim.
 */

static void
print_perm(perm)
    uint32 perm;
{

	char    string[20];

	(void) strcpy(string, "----------");

	switch (perm & S_IFMT) {

	case S_IFDIR:
		string[0] = 'd';
		break;

	case S_IFBLK:
		string[0] = 'b';
		break;

	case S_IFCHR:
		string[0] = 'c';
		break;

	case S_IFIFO:
		string[0] = 'p';
		break;
#if !defined(SYSV) || (SYSV > 3)
	case S_IFLNK:
		string[0] = 'l';
#endif
	}
	if (perm & S_IREAD)
		string[1] = 'r';
	if (perm & S_IWRITE)
		string[2] = 'w';
	if (perm & S_ISUID && perm & S_IEXEC)
		string[3] = 's';
	else if (perm & S_IEXEC)
		string[3] = 'x';
	else if (perm & S_ISUID)
		string[3] = 'S';

	if (perm & S_IRGRP)
		string[4] = 'r';
	if (perm & S_IWGRP)
		string[5] = 'w';
	if (perm & S_ISUID && perm & S_IXGRP)
		string[6] = 's';
	else if (perm & S_IXGRP)
		string[6] = 'x';
	else if (perm & S_ISUID)
		string[6] = 'l';

	if (perm & S_IROTH)
		string[7] = 'r';
	if (perm & S_IWOTH)
		string[8] = 'w';
	if (perm & S_ISVTX && perm & S_IXOTH)
		string[9] = 't';
	else if (perm & S_IXOTH)
		string[9] = 'x';
	else if (perm & S_ISVTX)
		string[9] = 'T';

	(void) printf("%s", string);
}

/*
 * generate a temporary filename, placing it into (s).  we assume that
 * space is already allocated for (s).
 */

int
fd_tempfilename_generate()
{
    char tmp[MAXPATHLEN+256];
    int fd;

    (void) strcpy(tmp, TEMPFILE_TEMPLATE);
    if ((char *) mktemp(tmp) == NULL) {
	perror("tempfilename_generate: mktemp()");
	exit(1);
    }

    if ((fd = open(tmp, O_RDWR | O_CREAT, 0600)) < 0) {
	perror("tempfilename_generate: open()");
	exit(1);
    }
    /* unlink right away to make sure no one can tamper with our file */
    unlink(tmp);

    return fd;
}

/*
 * read the entirety of input from file descriptor, copying into a file in /tmp.
 * we unlink the file to prevent anyone from accessing it.
 * we then return a file descriptor to that file.
 */

#define BSIZE  4096

int
fd_copy_to_tmp(fdin)
    int fdin;
{
    int readin;
    int fdout;
    struct stat statbuf;
    char buf[BSIZE];

    /* we don't need to copy from the fd if it's a regular file */
    if (fstat(fdin, &statbuf) < 0) {
	die_with_err("fd_copy_to_tmp: fstat()", NULL);
    }
    if ((statbuf.st_mode & S_IFMT) == S_IFREG)
        return fdin;

    fdout = fd_tempfilename_generate();

    while ((readin = read(fdin, buf, BSIZE)) != 0) {
        if (readin < 0) {
	    char *pc = (char *) malloc(100);
	    sprintf(pc, "%d", fdin);
	    die_with_err("fd_copy_to_tmp: read(%d)", pc);
	    exit(1);
	}
	if (write(fdout, buf, readin) != readin) {
	    die_with_err("fd_copy_to_tmp: write()", NULL);
	}
    }

    close(fdin);
    if (lseek(fdout, 0, SEEK_SET) != 0) {
	die_with_err("fd_copy_to_tmp: lseek() rewind error!", NULL);
    }

    return fdout;
}

int
file_copy_to_tmp(filename)
    char *filename;
{
    int fdin, fdout;

    if ((fdin = open(filename, O_RDONLY)) < 0) {
        die_with_err("couldn't open %s", filename);
    }

    fdout = fd_copy_to_tmp(fdin);
    return fdout;
}

#ifdef TEST
int debuglevel;
main() {
    int i;
    char s[64][1024];

    for (i = 0; i < 64; i++) {
	ltob64((int32) i, s[i]);
	printf("%d --> %s\n", i, s[i]);
    }

    for (i = 0; i < 64; i++) {
	int32 l;
	l = b64tol(s[i]);
	printf("%ld\n", l);

    }

}
#endif
