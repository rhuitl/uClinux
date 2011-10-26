#ident "$Id: gettydefs.c,v 4.1 1997/01/12 14:53:39 gert Exp $ Copyright (c) 1993 Gert Doering/Chris Lewis"

/* gettydefs.c
 *
 * Read /etc/gettydefs file, and permit retrieval of individual entries.
 *
 * Code in this module by Chris Lewis
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include "syslibs.h"

#include "mgetty.h"
#include "policy.h"

boolean verbose;

char * mydup _P1 ((s), register char *s)
{
    register char *p = (char *) malloc(strlen(s) + 1);
    if (!p) {
	lprintf(L_ERROR, "mydup can't malloc");
	exit(1);
    }
    strcpy(p, s);
    return(p);
}
#ifdef USE_GETTYDEFS

static char gettydefs_ID[] = "@(#)gettydefs.c compiled with USE_GETTYDEFS";

#include "tio.h"

struct modeword {
    char *name;
    tioflag_t turnon;
    tioflag_t turnoff;
    unsigned short metaon;
    unsigned short metaoff;
};

/*	Meta tokens */
#define SANE	0x0001
#define	ODDP	0x0002

#define	PARITY	0x0004
#define	NPARITY	0x0008

#define RAW	0x0010
#define	COOKED	0x0020

#define NL	0x0040
#define NNL	0x0080

#define LCASE	0x0100
#define NLCASE	0x0200

#define TABS	0x0400
#define	NTABS	0x0800

/* input modes */

static struct modeword iflags[] = {
    { "IGNBRK", IGNBRK, IGNBRK },
    { "BRKINT", BRKINT, BRKINT, SANE },
    { "IGNPAR", IGNPAR, IGNPAR, SANE },
    { "PARMRK", PARMRK, PARMRK },
    { "INPCK", INPCK, INPCK },
    { "ISTRIP", ISTRIP, ISTRIP, SANE },
    { "INLCR", INLCR, INLCR, 0, NNL },
    { "IGNCR", IGNCR, IGNCR, 0, NNL },
    { "ICRNL", ICRNL, ICRNL, (SANE|NL), NNL },
    { "IUCLC", IUCLC, IUCLC, LCASE, NLCASE },
    { "IXON", IXON, IXON, SANE },
    { "IXANY", IXANY, IXANY },
    { "IXOFF", IXOFF, IXOFF },
    { NULL }
};

/* output modes */

static struct modeword oflags[] = {
    { "OPOST", OPOST, OPOST, (SANE|COOKED), RAW },
    { "OLCUC", OLCUC, OLCUC, LCASE, NLCASE },
    { "ONLCR", ONLCR, ONLCR, NL, NNL },
    { "OCRNL", OCRNL, OCRNL, 0, NNL },
    { "ONOCR", ONOCR, ONOCR },
    { "ONLRET", ONLRET, ONLRET, NNL },
    { "OFILL", OFILL, OFILL },
    { "OFDEL", OFDEL, OFDEL },
    { "NLDLY", NLDLY, NLDLY },
    { "NL0", NL0, NLDLY },
    { "NL1", NL1, NLDLY },
    { "CR0", CR0, CRDLY },
    { "CR1", CR1, CRDLY },
    { "CR2", CR2, CRDLY },
    { "CR3", CR3, CRDLY },
    { "TAB0", TAB0, TABDLY, TABS },
    { "TAB1", TAB1, TABDLY },
    { "TAB2", TAB2, TABDLY },
    { "TAB3", TAB3, TABDLY, NTABS },
    { "BS0", BS0, BSDLY },
    { "BS1", BS1, BSDLY },
    { "VT0", VT0, VTDLY },
    { "VT1", VT1, VTDLY },
    { "FF0", FF0, FFDLY },
    { "FF1", FF1, FFDLY },
    { NULL }
};

/* control modes */

static struct modeword cflags[] = {
    { "B0", B0, CBAUD },
    { "B50", B50, CBAUD },
    { "B75", B75, CBAUD },
    { "B110", B110, CBAUD },
    { "B134", B134, CBAUD },
    { "B150", B150, CBAUD },
    { "B200", B200, CBAUD },
    { "B300", B300, CBAUD },
    { "B600", B600, CBAUD },
#ifdef B900
    { "B900", B900, CBAUD },
#endif
    { "B1200", B1200, CBAUD },
    { "B1800", B1800, CBAUD },
    { "B2400", B2400, CBAUD },
#ifdef B3600
    { "B3600", B3600, CBAUD },
#endif
    { "B4800", B4800, CBAUD },
#ifdef B7200
    { "B7200", B7200, CBAUD },
#endif
    { "B9600", B9600, CBAUD },
#ifdef B19200
    { "B19200", B19200, CBAUD },
#endif
#ifdef B38400
    { "B38400", B38400, CBAUD },
#endif
#ifdef B57600
    { "B57600", B57600, CBAUD },
#endif
#ifdef B76800
    { "B76800", B76800, CBAUD },
#endif
#ifdef B115200
    { "B115200", B115200, CBAUD },
#endif
#ifdef B230400
    { "B230400", B230400, CBAUD },
#endif
#ifdef B230400
    { "B230400", B230400, CBAUD },
#endif
#ifdef B460800
    { "B460800", B460800, CBAUD },
#endif
    { "EXTA", EXTA, CBAUD },
    { "EXTB", EXTB, CBAUD },
    { "CS5", CS5, CSIZE },
    { "CS6", CS6, CSIZE },
    { "CS7", CS7, CSIZE, (ODDP|PARITY) },
    { "CS8", CS8, CSIZE, (SANE|NPARITY) },
    { "CSTOPB", CSTOPB, CSTOPB },
    { "CREAD", CREAD, CREAD, SANE },
    { "PARENB", PARENB, PARENB, (ODDP|PARITY), (NPARITY) },
    { "PARODD", PARODD, PARODD, ODDP },
    { "HUPCL", HUPCL, HUPCL },
    { "CLOCAL", CLOCAL, CLOCAL },
/* Various handshaking defines */
#ifdef CTSCD
    { "CTSCD", CTSCD, CTSCD },
#endif
#ifdef CRTSCTS
    { "CRTSCTS", CRTSCTS, CRTSCTS },
#endif
#ifdef CRTSFL
    { "CRTSFL", CRTSFL, CRTSFL },
#endif
#ifdef RTSFLOW
    { "RTSFLOW", RTSFLOW, RTSFLOW },
    { "CTSFLOW", CTSFLOW, CTSFLOW },
#endif
#ifdef HDX
    { "HDX", HDX, HDX },
#endif
    { NULL }
};

/* line discipline */
static struct modeword lflags[] =  {
    { "ISIG", ISIG, ISIG, SANE },
    { "ICANON", ICANON, ICANON, (SANE|COOKED), RAW },
    { "XCASE", XCASE, XCASE, LCASE, NLCASE },
    { "ECHO", ECHO, ECHO, SANE },
    { "ECHOE", ECHOE, ECHOE },
    { "ECHOK", ECHOK, ECHOK, SANE },
    { "ECHONL", ECHONL, ECHONL },
    { "NOFLSH", NOFLSH, NOFLSH },
    { NULL }
};

/* c_cc special characters */
static struct modeword ccchars[] = {
    {"VINTR", VINTR, CINTR},
    {"VQUIT", VQUIT, CQUIT},
    {"VERASE", VERASE, CERASE},
    {"VKILL", VKILL, CKILL},
    {"VEOF", VEOF, CEOF},
#if defined(VEOL) && VEOL < TIONCC
    {"VEOL", VEOL, CEOL},
#endif
#if defined(CEOL2) && defined(VEOL2) && VEOL2 < TIONCC
    {"VEOL2", VEOL2, CEOL2},
#endif
#if defined(VSUSP) && VSUSP < TIONCC
    {"VSUSP", VSUSP, CSUSP},
#endif
#if defined(VSTART) && VSTART < TIONCC
    {"VSTART", VSTART, CSTART},
#endif
#if defined(VSTOP) && VSTOP < TIONCC
    {"VSTOP", VSTOP, CSTOP},
#endif
#if defined(VSWTCH) && VSWTCH < TIONCC
    {"VSWTCH", VSWTCH, CSWTCH},
#endif
/* SVR4.2 */
#if defined(VDSUSP) && VDSUSP < TIONCC
   {"VDSUSP", VDSUSP, CDSUSP},
#endif
#if defined(VREPRINT) && VREPRINT < TIONCC
   {"VREPRINT", VREPRINT, CRPRNT},
#endif
#if defined(VDISCARD) && VDISCARD < TIONCC
   {"VDISCARD", VDISCARD, CFLUSH},
#endif
#if defined(VWERASE) && VWERASE < TIONCC
   {"VWERASE", VWERASE, CWERASE},
#endif
#if defined(VLNEXT) && VLNEXT < TIONCC
   {"VLNEXT", VLNEXT, CLNEXT},
#endif
    {"VMIN", VMIN, 0},
    {"VTIME", VTIME, 0},
    { NULL }
};

struct modeword metatokens[] = {
    { "SANE", SANE },
    { "ODDP", ODDP },

    { "PARITY", PARITY },
    { "EVENP", PARITY },
    { "-ODDP", NPARITY },
    { "-PARITY", NPARITY },
    { "-EVENP", NPARITY },

    { "RAW", RAW },
    { "-RAW", COOKED },
    { "COOKED", COOKED },

    { "NL", NL },
    { "-NL", NNL },

    { "LCASE", LCASE },
    { "-LCASE", NLCASE },

    { "TABS", TABS },
    { "-TABS", NTABS },
    { "TAB3", NTABS },

    { NULL }
};

#define GDCHUNK	5

GDE *gdep = (GDE *) NULL;
GDE *cur = (GDE *) NULL;
static int cntalloc = 0;

static struct modeword *
findmode _P2 ((modes, tok), struct modeword *modes, register char *tok)
{
    for( ; modes->name; modes++)
	if (strcmp(modes->name, tok) == 0)
	    return(modes);
    return((struct modeword *) NULL);
}

static void
metaset _P3((tc, modes, key), tioflag_t *tc, struct modeword *modes, int key)
{
    for ( ; modes->name; modes++) {
	if (modes->metaon&key)
	    *tc = (*tc & ~ modes->turnoff) | modes->turnon;
	if (modes->metaoff&key)
	    *tc = (*tc & ~ modes->turnoff);
    }
}

static void
parsetermio _P2((ti, str), TIO *ti, char *str)
{
    register char *p;
    struct modeword *m;
    tioflag_t *flag;
    int metakey;

    /* initialize c_cc[] array (tio_* doesn't init INTR/ERASE!) */
    tio_default_cc( ti );
    ti->c_cc[VINTR] = CINTR;
    ti->c_cc[VERASE] = CERASE;

#ifndef POSIX_TERMIOS
    ti->c_line = 0;
#endif

    for (p = str; *p; p++)
	if (islower(*p))
	    *p = toupper(*p);

    while ( (p = strtok(str, " \t")) != NULL ) {
	int not = FALSE;

	str = NULL;

	metakey = 0;

	if (strcmp(p, "EK") == 0) {
	    ti->c_cc[VERASE] = '#';
	    ti->c_cc[VKILL] = CKILL;
	    continue;
	}

	for (m = metatokens; m->name; m++)
	    if (strcmp(p, m->name) == 0) {
		metakey = m->turnon;
		break;
	    }
	
	if (metakey) {
	    metaset(&ti->c_lflag, lflags, metakey);
	    metaset(&ti->c_oflag, oflags, metakey);
	    metaset(&ti->c_iflag, iflags, metakey);
	    metaset(&ti->c_cflag, cflags, metakey);
	    continue;
	}

	if (*p == '-') {
	    not = TRUE;
	    p++;
	}

	if      ((m = findmode(lflags, p)) != NULL)
	    flag = &ti->c_lflag;
	else if ((m = findmode(oflags, p)) != NULL)
	    flag = &ti->c_oflag;
	else if ((m = findmode(iflags, p)) != NULL)
	    flag = &ti->c_iflag;
	else if ((m = findmode(cflags, p)) != NULL)
	    flag = &ti->c_cflag;
	if (m) {
	    if (not)
		*flag = (*flag & ~ m->turnoff);
	    else
		*flag = (*flag & ~ m->turnoff) | m->turnon;
	} else {
	    if ((m = findmode(ccchars, p)) != NULL) {
		char *p2;
		p2 = strtok(str, " \t");
		if (!p2) {
		    if (verbose)
			fprintf(stderr, "No value after %s\n", p);
		    return;
		}
		if (*p2 == '\\')
		    switch(*(p2+1)) {
			case 'n': *p2 = '\n'; break;
			case 'r': *p2 = '\r'; break;
			case 'b': *p2 = '\010'; break;
			case 'v': *p2 = '\013'; break;
			case 'g': *p2 = '\007'; break;
			case 'f': *p2 = '\f'; break;
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7': {
			    char tbuf[4];
			    strncpy(tbuf, p2+1, 3);
			    tbuf[3] = '\0';
			    *p2 = strtol(tbuf, (char **) NULL, 8);
			    break;
			}
			default:
			    *p2 = *(p2+1);
		    }
		else if (*p2 == '^')		/* ^x means C-x, ^? is DEL */
		    *p2 = (*(p2+1) == '?')? 0x7f : *(p2+1) - '@';

		ti->c_cc[m->turnon] = *p2;
	    } else
		if (verbose)
		    fprintf(stderr, "Can't parse %s\n", p);
	}
    }

}

static char *
stripblanks _P1 ((s), register char *s)
{
    register char *p;
    while(*s && isspace(*s)) s++;
    p = s;
    while(*p && !isspace(*p)) p++;
    *p = '\0';
    return(s);
}

#define	GETTYBUFSIZE	(10*BUFSIZ)

int
getentry _P3((entry, elen, f), char *entry, int elen, FILE *f) {
    char buf[BUFSIZ*2];
    register char *p;

    entry[0] = '\0';

    do {
	if (!fgets(buf, sizeof(buf), f))
	    return(0);
	for (p = buf; isspace(*p); p++);
    } while(*p == '#' || *p == '\n');

    p = strchr(buf, '\n');
    if (p)
	*p = '\0';
    strcat(entry, buf);

    while (1) {
	if (!fgets(buf, sizeof(buf), f))
	    break;
	p = strchr(buf, '\n');
	if (p)
	    *p = '\0';
	for (p = buf; isspace(*p); p++);
	if (!*p)
	    break;
	strcat(entry, " ");
	strcat(entry, p);
    }
    return(1);
}

/*
 * loads all of the entries from the gettydefs file
 * returns 0 if it fails.
 */
int
loadgettydefs _P1((file), char *file ) {
    FILE *gd = fopen(file, "r");
    char buf[GETTYBUFSIZE];
    register char *p;
    char *tag, *prompt, *nexttag, *before, *after;

    if (!gd) {
	lprintf(L_WARN, "Can't open %s\n", file);
	return(0);
    }

    while(getentry(buf, sizeof(buf), gd)) {
	
	p = buf;

	tag = strtok(p, "#");
	if (!tag)
	    continue;
	tag = stripblanks(tag);
	tag = mydup(tag);

	before = strtok(NULL, "#");
	if (!before)
	    continue;

	after = strtok(NULL, "#");
	if (!after)
	    continue;

	prompt = strtok(NULL, "#");
	if (!prompt)
	    continue;

	/* do NOT escape prompt here - it may contain \D and \T, and
	 * for that, the real time at login should be used
	 */
	prompt = mydup(prompt);

	nexttag = strtok(NULL, "#");
	if (!nexttag)
	    continue;

	p = strchr(nexttag, '\n');
	if (p)
	    *p = '\0';

	nexttag = stripblanks(nexttag);
	nexttag = mydup(nexttag);

#ifdef NEVER
	printf("tag: %s\nbefore: %s\nafter: %s\nprompt: %s\nnexttag: %s\n\n",
	    tag, before, after, prompt, nexttag);
#endif

	if (cur - gdep >= cntalloc-2) {
	    GDE *sav;
	    sav = gdep;
	    if (!gdep) {
		gdep = (GDE *) malloc(sizeof(GDE) * GDCHUNK);
		cur = gdep;
	    } else {
		gdep = (GDE *) realloc(gdep, sizeof(GDE) * (GDCHUNK + cntalloc));
		cur = gdep + (cur - sav);
	    }
	    cntalloc += GDCHUNK;
	}

	memset(cur, sizeof(*cur), '\0');
	
	cur->tag = tag;
	cur->prompt = prompt;
	cur->nexttag = nexttag;
	parsetermio(&cur->before, before);
	parsetermio(&cur->after, after);
	if (verbose)
	    printf("Processed `%s' gettydefs entry\n", tag);
	cur++;
	cur->tag = (char *) NULL;
    }
    fclose(gd);
    return(1);
}

GDE *
getgettydef _P1 ((s), register char *s)
{
    for (cur = gdep; cur && cur->tag; cur++)
	if (strcmp(cur->tag, s) == 0)
	    return(cur);
    if (gdep && gdep->tag) {
	lprintf(L_WARN, "getgettydef(%s) entry not found using %s",
	    s, gdep->tag);
	return(gdep);
    }
    lprintf(L_WARN, "getgettydef(%s) no entry found", s);
    return((GDE *) NULL);
}

void
dumpflag _P3((type, modes, flag),
	     char *type,
	     struct modeword *modes, tioflag_t flag)
{
    printf("%s: %08lo", type, (unsigned long) flag);
    for(; modes->name; modes++)
	if ((flag&modes->turnoff) == modes->turnon)
	    printf(" %s", modes->name);
    putchar('\n');
}

void
dump _P2((ti, s), TIO *ti, char *s)
{
    register int i;
    register struct modeword *modes;

    printf("%s:", s);
    dumpflag("\tiflags", iflags, ti->c_iflag);
    dumpflag("\toflags", oflags, ti->c_oflag);
    dumpflag("\tcflags", cflags, ti->c_cflag);
    dumpflag("\tlflags", lflags, ti->c_lflag);
    printf("\tc_cc:\t");
    for (i = 0; i < TIONCC; i++) {
	if (i == 6)
	    printf("\n\t\t");
	for (modes = ccchars; modes->name; modes++)
	    if (modes->turnon == i) {
		printf("%s(", modes->name);
		break;
	    }
	if (!modes->name)	/* skip unallocated ones */
	    continue;
	/* Yeah, I know.  But who's ever heard of getty on a EBCDIC system ;-) */
	if (ti->c_cc[i] < ' ')
	    printf("^%c", ti->c_cc[i] + '@');
	else if (ti->c_cc[i] == (0xff & _POSIX_VDISABLE))
	    printf("disabled");
	else if (ti->c_cc[i] >= 0x7f)
	    printf("\\%03o", 0xff&ti->c_cc[i]);
	else
	    putchar(ti->c_cc[i]);
	printf(") ");
    }
    printf("\n\n");
}

static void 
spew _P1 ((gd), GDE *gd)
{
    printf("tag: `%s'\nprompt: `%s'\nnexttag: `%s'\n",
	gd->tag, gd->prompt, gd->nexttag);
    dump(&gd->before, "before");
    dump(&gd->after, "after");
    printf("\n");
}

void
dumpgettydefs _P1((file), char *file) {
    if (! loadgettydefs(file)) {
	fprintf(stderr, "Couldn't read %s\n", file);
	exit(1);
    }
    printf("loaded entries:\n");
    for (cur = gdep; cur->tag; cur++)
	spew(cur);

}
#endif
