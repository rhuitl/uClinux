#define Extern extern
#include <sys/types.h>
#include <signal.h>

#include <errno.h>
#include <setjmp.h>
#include <stddef.h>
#include <time.h>
#include <sys/times.h>
#include <sys/stat.h>
#include <sys/wait.h>
#undef NULL
#include "sh.h"
#include <unistd.h>

#define FREE 32767
int loop_is_called = 0;
int loop_last_areanum = 0;

static void catchsubint()
{
	isbreak = 1;
	longjmp(failpt, 1);
}

static void catchsubquit()
{
	isbreak = 1;
	longjmp(failpt, 1);
}


/* -------- exec.c -------- */
/* #include "sh.h" */

/*
 * execute tree
 */

static	char	*signame[] = {
	"Signal 0",
	"Hangup",
	(char *)NULL,	/* interrupt */
	"Quit",
	"Illegal instruction",
	"Trace/BPT trap",
	"Abort",
	"Bus error",
	"Floating Point Exception",
	"Killed",
	"SIGUSR1",
	"SIGSEGV",
	"SIGUSR2",
	(char *)NULL,	/* broken pipe */
	"Alarm clock",
	"Terminated",
};
#define	NSIGNAL (sizeof(signame)/sizeof(signame[0]))

static int set_is_called = 0;
_PROTOTYPE(static int forkexec, (struct op *t, int *pin, int *pout, int act, char **wp, int *pforked ));
_PROTOTYPE(int iosetup, (struct ioword *iop, int pipein, int pipeout ));
_PROTOTYPE(static void echo, (char **wp ));
_PROTOTYPE(static struct op **find1case, (struct op *t, char *w ));
_PROTOTYPE(static struct op *findcase, (struct op *t, char *w ));
_PROTOTYPE(static void brkset, (struct brkcon *bc ));
_PROTOTYPE(int dolabel, (void));
_PROTOTYPE(int dochdir, (struct op *t ));
_PROTOTYPE(int doshift, (struct op *t ));
_PROTOTYPE(int dologin, (struct op *t ));
_PROTOTYPE(int doumask, (struct op *t ));
_PROTOTYPE(int doexec, (struct op *t ));
_PROTOTYPE(int dodot, (struct op *t ));
_PROTOTYPE(int dowait, (struct op *t ));
_PROTOTYPE(int doread, (struct op *t ));
_PROTOTYPE(int doeval, (struct op *t ));
_PROTOTYPE(int dotrap, (struct op *t ));
_PROTOTYPE(int getsig, (char *s ));
_PROTOTYPE(void setsig, (int n, void (*f)()));
_PROTOTYPE(int getn, (char *as ));
_PROTOTYPE(int dobreak, (struct op *t ));
_PROTOTYPE(int docontinue, (struct op *t ));
_PROTOTYPE(static int brkcontin, (char *cp, int val ));
_PROTOTYPE(int doexit, (struct op *t ));
_PROTOTYPE(int doexport, (struct op *t ));
_PROTOTYPE(int doreadonly, (struct op *t ));
_PROTOTYPE(static void rdexp, (char **wp, void (*f)(), int key));
_PROTOTYPE(static void badid, (char *s ));
_PROTOTYPE(int doset, (struct op *t ));
_PROTOTYPE(void varput, (char *s, int out ));
_PROTOTYPE(int dotimes, (void));

int
execute(t, pin, pout, act)
register struct op *t;
int *pin, *pout;
int act;
{
	register struct op *t1;
	int i, pv[2], rv, child, a;
	char *cp, **wp, **wp2;
	struct var *vp;
	struct brkcon bc;

#if __GNUC__
        /* Avoid longjmp clobbering */
        (void) &i;
        (void) &rv;
        (void) &wp;
#endif

	if (t == NULL)
		return(0);
	rv = 0;
	a = areanum++;
	if (areanum == FREE) {/* get around of FREE */
		areanum++;
	}
	isbreak = 0;
	wp = (wp2 = t->words) != NULL
	     ? eval(wp2, t->type == TCOM ? DOALL : DOALL & ~DOKEY)
	     : NULL;

	switch(t->type) {
	case TPAREN:
	case TCOM:
		rv = forkexec(t, pin, pout, act, wp, &child);
		if (child) {
			exstat = rv;
			leave();
		}
		break;

	case TPIPE:
		if ((rv = openpipe(pv)) < 0)
			break;
		pv[0] = remap(pv[0]);
		pv[1] = remap(pv[1]);
		(void) execute(t->left, pin, pv, 0);
		rv = execute(t->right, pv, pout, 0);
		break;

	case TLIST:
		(void) execute(t->left, pin, pout, 0);
		rv = execute(t->right, pin, pout, 0);
		break;

	case TASYNC:
	{
		void *sp = dupstate();

		i = vfork();
		if (i != 0) {
			restorestate(sp);
			if (i != -1) {
				setval(lookup("!"), putn(i));
				if (pin != NULL)
					closepipe(pin);
				if (talking) {
					prs(putn(i));
					prs("\n");
				}
			} else
				rv = -1;
			setstatus(rv);
		} else {
			signal(SIGINT, SIG_IGN);
			signal(SIGQUIT, SIG_IGN);
			if (talking)
				signal(SIGTERM, SIG_DFL);
			talking = 0;
			if (pin == NULL) {
				close(0);
				open("/dev/null", 0);
			}
			/* for background process */
			if(setpgid(getpid(), getpid()) == -1)
				exit(1);
			exit(execute(t->left, pin, pout, FEXEC));
		}
	}
		break;

	case TOR:
	case TAND:
		rv = execute(t->left, pin, pout, 0);
		if ((t1 = t->right)!=NULL && (rv == 0) == (t->type == TAND))
			rv = execute(t1, pin, pout, 0);
		break;

	case TFOR:
		if (wp == NULL) {
			wp = dolv+1;
			if ((i = dolc) < 0)
				i = 0;
		} else {
			i = -1;
			while (*wp++ != NULL)
				;			
		}
		vp = lookup(t->str);
		while (setjmp(bc.brkpt))
			if (isbreak){
				goto broken;
			}
		brkset(&bc);
		for (t1 = t->left; i-- && *wp != NULL;) {
			setval(vp, *wp++);
			rv = execute(t1, pin, pout, 0);
		}
		brklist = brklist->nextlev;
		break;

	case TWHILE:
	case TUNTIL:
		while (setjmp(bc.brkpt))
			if (isbreak)
				goto broken;
		brkset(&bc);
		t1 = t->left;
		if(!loop_is_called ) {
			loop_is_called = areanum;
		}
		while ((execute(t1, pin, pout, 0) == 0) == (t->type == TWHILE))
			rv = execute(t->right, pin, pout, 0);
		brklist = brklist->nextlev;
		break;

	case TIF:
	case TELIF:
	 	if (t->right != NULL) {
		rv = !execute(t->left, pin, pout, 0) ?
			execute(t->right->left, pin, pout, 0):
			execute(t->right->right, pin, pout, 0);
		}
		break;

	case TCASE:
		if ((cp = evalstr(t->str, DOSUB|DOTRIM)) == 0)
			cp = "";
		if ((t1 = findcase(t->left, cp)) != NULL)
			rv = execute(t1, pin, pout, 0);
		break;

	case TBRACE:
/*
		if (iopp = t->ioact)
			while (*iopp)
				if (iosetup(*iopp++, pin!=NULL, pout!=NULL)) {
					rv = -1;
					break;
				}
*/
		if (rv >= 0 && (t1 = t->left))
			rv = execute(t1, pin, pout, 0);
		break;
	}

broken:
	t->words = wp2;
	if (isbreak == 1){
		signal(SIGINT, catchint);
		signal(SIGQUIT, catchquit);
	}
	isbreak = 0;
	freehere(areanum);
	freearea(areanum);
	areanum = a;
	if (talking && intr) {
		closeall();
		fail();
	}
	if ((i = trapset) != 0) {
		trapset = 0;
		runtrap(i);
	}
	return(rv);
}

static int
forkexec(t, pin, pout, act, wp, pforked)
register struct op *t;
int *pin, *pout;
int act;
char **wp;
int *pforked;
{
	int i, rv, (*shcom)();
	register int f;
	char *cp = NULL;
	struct ioword **iopp;
	int resetsig;
	char **owp;

	int *hpin = pin;
	int *hpout = pout;
	int hforked;
	char *hwp;
	int htalking;
	int hintr;
	int hbrklist;
	int hexecflg;
	int forkp;

#if __GNUC__
        /* Avoid longjmp clobbering */
        (void) &shcom;
        (void) &resetsig;
        (void) &cp;
        (void) &owp;
        (void) &pin;
        (void) &pout;
        (void) &wp;
#endif
	owp = wp;
	resetsig = 0;
	*pforked = 0;
	forkp = 0;
	shcom = NULL;
	rv = -1;	/* system-detected error */
	if (t->type == TCOM) {
		while ((cp = *wp++) != NULL)
			;
		cp = *wp;

		/* strip all initial assignments */
		/* not correct wrt PATH=yyy command  etc */
		if (flag['x'])
			echo (cp ? wp: owp);
		if (cp == NULL && t->ioact == NULL) {
			while ((cp = *owp++) != NULL && assign(cp, COPYV))
				;
			return(setstatus(0));
		}
		else if (cp != NULL)
			shcom = inbuilt(cp);
	}
	t->words = wp;
	f = act;
	if ((shcom == NULL && (f & FEXEC) == 0) || ((pin == NULL && pout != NULL) && shcom != NULL && shcom != doexec)) {
		forkp = 1;
		hpin = pin;
		hpout = pout;
		hforked = *pforked;
		hwp = *wp;
		htalking = talking;
		hintr = intr;
		hbrklist = (int)brklist;
		hexecflg = execflg;

		i = vfork();
		if (i != 0) {
                	/* who wrote this crappy non vfork safe shit? */
			pin = hpin;
			pout = hpout;
			*pforked = hforked;
			*wp = hwp;
			talking = htalking;
			intr = hintr;
			brklist = (struct brkcon *)hbrklist;
			execflg = hexecflg;

			*pforked = 0;
			if (i == -1)
				return(rv);
			if (pin != NULL)
				closepipe(pin);
			return(pout==NULL? setstatus(waitfor(i,0)): 0);
		}

#ifdef EMBED
/* We cannot allow a return here */
#define RETURN(x)	if (forkp) _exit(1); else return(x)
#define EXIT(x)		if (forkp) _exit(x); else exit(x)
#else
#define RETURN(x)	return (x);
#define EXIT(x)		exit(x)
#endif
		if (talking) {
			signal(SIGINT, SIG_IGN);
			signal(SIGQUIT, SIG_IGN);
			resetsig = 1;
		}
		talking = 0;
		intr = 0;
		(*pforked)++;
		brklist = 0;
		execflg = 0;
	}	
	if (owp != NULL)
		while ((cp = *owp++) != NULL && assign(cp, COPYV))
			if (shcom == NULL)
				export(lookup(cp));
	if ((pin != NULL || pout != NULL) && shcom != NULL && shcom != doexec) {

		if (pin == NULL ){ /* to pipe */
			dup2(pout[1], 1);
			EXIT(setstatus((*shcom)(t)));
		}
		else { /* from pipe*/
			err("piping from shell builtins not yet done");
			RETURN(-1);
		}
	}

	if (pin != NULL) {
		dup2(pin[0], 0);
		closepipe(pin);
	}
	if (pout != NULL) {
		dup2(pout[1], 1);
		closepipe(pout);
	}
#if 0
	if ((iopp = t->ioact) != NULL) {
		if (shcom != NULL && shcom != doexec) {
			prs(cp);
			err(": cannot redirect shell command");
			RETURN(-1);
		}
		while (*iopp)
			if (iosetup(*iopp++, pin!=NULL, pout!=NULL)){
				RETURN(rv);
			}
	}
#else
	if ((iopp = t->ioact) != NULL) {
		if (shcom == NULL || (shcom == doexec)) 
			while (*iopp)
				if (iosetup(*iopp++, pin!=NULL, pout!=NULL)){
					RETURN(rv);
				}
	}
#endif
	if (shcom)
		RETURN(setstatus((*shcom)(t)));
	/* should use FIOCEXCL */
	for (i=FDBASE; i<NOFILE; i++)
		close(i);
	if (resetsig) {
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
	}
	if (t->type == TPAREN)
		EXIT(execute(t->left, NOPIPE, NOPIPE, FEXEC));
	if (wp[0] == NULL)
		EXIT(0);

	cp = rexecve(wp[0], wp, makenv());
	prs(wp[0]); prs(": "); warn(cp);
	if (!execflg)
		trap[0] = NULL;
#ifdef EMBED
	if (forkp) _exit(1); else leave();
#else
	leave();
#endif
	/* NOTREACHED */
#undef EXIT
#undef RETURN
}

/*
 * 0< 1> are ignored as required
 * within pipelines.
 */
int
iosetup(iop, pipein, pipeout)
register struct ioword *iop;
int pipein, pipeout;
{
	register int u;
	char *msg;
	char *cp = NULL;

	if (iop->io_unit == IODEFAULT)	/* take default */
		iop->io_unit = iop->io_flag&(IOREAD|IOHERE)? 0: 1;
	if (pipein && iop->io_unit == 0)
		return(0);
	if (pipeout && iop->io_unit == 1)
		return(0);
	msg = iop->io_flag&(IOREAD|IOHERE)? "open": "create";
	if ((iop->io_flag & IOHERE) == 0) {
		cp = iop->io_name;
		if ((cp = evalstr(cp, DOSUB|DOTRIM)) == NULL)
			return(1);
	}
	if (iop->io_flag & IODUP) {
		if (cp[1] || (!digit(*cp) && *cp != '-')) {
			prs(cp);
			err(": illegal >& argument");
			return(1);
		}
		if (*cp == '-')
			iop->io_flag = IOCLOSE;
		iop->io_flag &= ~(IOREAD|IOWRITE);
	}
	switch (iop->io_flag) {
	case IOREAD:
		u = open(cp, 0);
		break;

	case IOHERE:
	case IOHERE|IOXHERE:
		u = herein(iop->io_name, iop->io_flag&IOXHERE);
		cp = "here file";
		break;

	case IOWRITE|IOCAT:
		if ((u = open(cp, 1)) >= 0) {
			lseek(u, (long)0, 2);
			break;
		}
	case IOWRITE:
		u = creat(cp, 0666);
		break;

	case IODUP:
		u = dup2(*cp-'0', iop->io_unit);
		break;

	case IOCLOSE:
		close(iop->io_unit);
		return(0);
	default:
		u = -1;
		break;
	}
	if (u < 0) {
		prs(cp);
		prs(": cannot ");
		warn(msg);
		exit(1); 
	}
	 else
		{
		if (u != iop->io_unit) {
			dup2(u, iop->io_unit);
			close(u);
		}
	}
	return(0);
}

static void
echo(wp)
register char **wp;
{
	register int i;

	prs("+");
	for (i=0; wp[i]; i++) {
		if (i)
			prs(" ");
		prs(wp[i]);
	}
	prs("\n");
}

static struct op **
find1case(t, w)
struct op *t;
char *w;
{
	register struct op *t1;
	struct op **tp;
	register char **wp, *cp;

	if (t == NULL)
		return((struct op **)NULL);
	if (t->type == TLIST) {
		if ((tp = find1case(t->left, w)) != NULL)
			return(tp);
		t1 = t->right;	/* TPAT */
	} else
		t1 = t;
	for (wp = t1->words; *wp;)
		if ((cp = evalstr(*wp++, DOSUB)) && gmatch(w, cp))
			return(&t1->left);
	return((struct op **)NULL);
}

static struct op *
findcase(t, w)
struct op *t;
char *w;
{
	register struct op **tp;

	return((tp = find1case(t, w)) != NULL? *tp: (struct op *)NULL);
}

/*
 * Enter a new loop level (marked for break/continue).
 */
static void
brkset(bc)
struct brkcon *bc;
{
	bc->nextlev = brklist;
	brklist = bc;
}

/*
 * Wait for the last process created.
 * Print a message for each process found
 * that was killed by a signal.
 * Ignore interrupt signals while waiting
 * unless `canintr' is true.
 */
int
waitfor(lastpid, canintr)
register int lastpid;
int canintr;
{
	register int pid, rv;
	int s;
	int oheedint = heedint;

	heedint = 0;
	rv = 0;
	do {
		pid = wait(&s);
		if (pid == -1) {
			if (errno != EINTR || canintr)
				break;
		} else {
			if ((rv = WAITSIG(s)) != 0) {
				if (rv < NSIGNAL) {
					if (signame[rv] != NULL) {
						if (pid != lastpid) {
							prn(pid);
							prs(": ");
						}
						prs(signame[rv]);
					}
				} else {
					if (pid != lastpid) {
						prn(pid);
						prs(": ");
					}
					prs("Signal "); prn(rv); prs(" ");
				}
				if (WAITCORE(s))
					prs(" - core dumped");
				if (rv >= NSIGNAL || signame[rv])
					prs("\n");
				rv = -1;
			} else
				rv = WAITVAL(s);
		}
	} while (pid != lastpid);
	heedint = oheedint;
	if (intr) {
		if (talking) {
			if (canintr)
				intr = 0;
		} else {
			if (exstat == 0) exstat = rv;
			onintr(0);
		}
	}
	return(rv);
}

int
setstatus(s)
register int s;
{
	exstat = s;
	setval(lookup("?"), putn(s));
	return(s);
}

/*
 * PATH-searching interface to execve.
 * If getenv("PATH") were kept up-to-date,
 * execvp might be used.
 */
char *
rexecve(c, v, envp)
char *c, **v, **envp;
{
	register int i;
	register char *sp, *tp;
	int eacces = 0, asis = 0;

	sp = any('/', c)? "": path->value;
	asis = *sp == '\0';
	while (asis || *sp != '\0') {
		asis = 0;
		tp = e.linep;
		for (; *sp != '\0'; tp++)
			if ((*tp = *sp++) == ':') {
				asis = *sp == '\0';
				break;
			}
		if (tp != e.linep)
			*tp++ = '/';
		for (i = 0; (*tp++ = c[i++]) != '\0';)
			;
		execve(e.linep, v, envp);
		switch (errno) {
		case ENOEXEC:
			*v = e.linep;
			tp = *--v;
			*v = e.linep;
			execve("/bin/sh", v, envp);
			*v = tp;
			return("no Shell");

		case ENOMEM:
			return("program too big");

		case E2BIG:
			return("argument list too long");

		case EACCES:
			eacces++;
			break;
		}
	}
	return(errno==ENOENT ? "not found" : "cannot execute");
}

/*
 * Run the command produced by generator `f'
 * applied to stream `arg'.
 */
int
run(argp, f)
struct ioarg *argp;
int (*f)();
{
	struct op *otree;
	struct wdblock *swdlist;
	struct wdblock *siolist;
	jmp_buf ev, rt;
	xint *ofail;
	int rv;

#if __GNUC__
        /* Avoid longjmp clobbering */
        (void) &rv;
#endif
	areanum++;
	if (areanum == FREE) {/* get around of FREE */
	areanum++;
	}
	swdlist = wdlist;
	siolist = iolist;
	otree = outtree;
	ofail = failpt;
	rv = -1;
	errpt = (xint *) ev;
	if (newenv(setjmp(ev)) == 0) {
		wdlist = 0;
		iolist = 0;
		pushio(argp, f);
		e.iobase = e.iop;
		yynerrs = 0;
		failpt = (xint *) rt;
		if (setjmp(rt) == 0 && yyparse() == 0)
			rv = execute(outtree, NOPIPE, NOPIPE, 0);
		quitenv();
	}
	wdlist = swdlist;
	iolist = siolist;
	failpt = ofail;
	outtree = otree;
	freearea(areanum--);
	return(rv);
}

/* -------- do.c -------- */
/* #include "sh.h" */

/*
 * built-in commands: doX
 */

int
dolabel()
{
	return(0);
}

int
dochdir(t)
register struct op *t;
{
	register char *cp, *er;

	if ((cp = t->words[1]) == NULL && (cp = homedir->value) == NULL)
		er = ": no home directory";
	else if(chdir(cp) < 0)
		er = ": bad directory";
	else
		return(0);
	prs(cp != NULL? cp: "cd");
	err(er);
	return(1);
}

int
doshift(t)
register struct op *t;
{
	register int n;

	n = t->words[1]? getn(t->words[1]): 1;
	if(dolc < n) {
		err("nothing to shift");
		return(1);
	}
	dolv[n] = dolv[0];
	dolv += n;
	dolc -= n;
	setval(lookup("#"), putn(dolc));
	return(0);
}

/*
 * execute login and newgrp directly
 */
int
dologin(t)
struct op *t;
{
	register char *cp;

	if (talking) {
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
	}
	cp = rexecve(t->words[0], t->words, makenv());
	prs(t->words[0]); prs(": "); err(cp);
	return(1);
}

int
doumask(t)
register struct op *t;
{
	register int i, n;
	register char *cp;

	if ((cp = t->words[1]) == NULL) {
		i = umask(0);
		umask(i);
		for (n=3*4; (n-=3) >= 0;)
			myputc('0'+((i>>n)&07));
		myputc('\n');
	} else {
		for (n=0; *cp>='0' && *cp<='9'; cp++)
			n = n*8 + (*cp-'0');
		umask(n);
	}
	return(0);
}

int
doexec(t)
register struct op *t;
{
	register int i;
	jmp_buf ex;
	xint *ofail;

	t->ioact = NULL;
	for(i = 0; (t->words[i]=t->words[i+1]) != NULL; i++)
		;
	if (i == 0)
		return(1);
	execflg = 1;
	ofail = failpt;
	failpt = (xint *) ex;
	if (setjmp(ex) == 0)
		execute(t, NOPIPE, NOPIPE, FEXEC);
	failpt = ofail;
	execflg = 0;
	return(1);
}

int
dodot(t)
struct op *t;
{
	register int i;
	register char *sp, *tp;
	char *cp;

	if ((cp = t->words[1]) == NULL)
		return(0);
	sp = any('/', cp)? ":": path->value;
	while (*sp) {
		tp = e.linep;
		while (*sp && (*tp = *sp++) != ':')
			tp++;
		if (tp != e.linep)
			*tp++ = '/';
		for (i = 0; (*tp++ = cp[i++]) != '\0';)
			;
		if ((i = open(e.linep, 0)) >= 0) {
			exstat = 0;
			next(remap(i));
			return(exstat);
		}
	}
	prs(cp);
	err(": not found");
	return(-1);
}

int
dowait(t)
struct op *t;
{
	register int i;
	register char *cp;

	if ((cp = t->words[1]) != NULL) {
		i = getn(cp);
		if (i == 0)
			return(0);
	} else
		i = -1;
	setstatus(waitfor(i, 1));
	return(0);
}

int
doread(t)
struct op *t;
{
	register char *cp, **wp;
	register int nb = 0;
	register int  nl = 0;

	int fp = 0;

	if (t->words[1] == NULL) {
/*
 * Code reduction for embedded product with no attended system.
 * If you want to see the usage help message, just add CFLAGS += -DENABLE_USAGE
 * in compiler options list or Makefile.
 */
#if defined(ENABLE_USAGE)
		err("Usage: read name ...");
#endif
		return(1);
	}

	/* reading from a file in (*t->ioact)->io_name if following holds */ 
	if(t->ioact && (*t->ioact) && (*t->ioact)->io_name ) fp = open((*t->ioact)->io_name, O_RDONLY);

	for (wp = t->words+1; *wp; wp++) {
		for (cp = e.linep; !nl && cp < elinep-1; cp++){
			if ((nb = read(fp, cp, sizeof(*cp))) != sizeof(*cp) ||
			    (nl = (*cp == '\n')) ||
			    (wp[1] && any(*cp, ifs->value)))
				break;
		}
		*cp = 0;
		nb = cp - e.linep;
		if (nb <= 0)
			break;
		setval(lookup(*wp), e.linep);
	}
	if (fp) close (fp);
	return(nb <= 0);
}

int
doeval(t)
register struct op *t;
{
	return(RUN(awordlist, t->words+1, wdchar));
}

int
dotrap(t)
register struct op *t;
{
	register int  n, i;
	register int  resetsig;

	if (t->words[1] == NULL) {
		for (i=0; i<=_NSIG; i++)
			if (trap[i]) {
				prn(i);
				prs(": ");
				prs(trap[i]);
				prs("\n");
			}
		return(0);
	}
	resetsig = digit(*t->words[1]);
	for (i = resetsig ? 1 : 2; t->words[i] != NULL; ++i) {
		n = getsig(t->words[i]);
		xfree(trap[n]);
		trap[n] = 0;
		if (!resetsig) {
			if (*t->words[1] != '\0') {
				trap[n] = strsave(t->words[1], 0);
				setsig(n, sig);
			} else
				setsig(n, SIG_IGN);
		} else {
			if (talking)
				if (n == SIGINT)
					setsig(n, onintr);
				else
					setsig(n, n == SIGQUIT ? SIG_IGN 
							       : SIG_DFL);
			else
				setsig(n, SIG_DFL);
		}
	}
	return(0);
}

int
getsig(s)
char *s;
{
	register int n;

	if ((n = getn(s)) < 0 || n > _NSIG) {
		err("trap: bad signal number");
		n = 0;
	}
	return(n);
}

void
setsig(n, f)
register int n;
_PROTOTYPE(void (*f), (int));
{
	if (n == 0)
		return;
	if (signal(n, SIG_IGN) != SIG_IGN || ourtrap[n]) {
		ourtrap[n] = 1;
		signal(n, f);
	}
}

int
getn(as)
char *as;
{
	register char *s;
	register int n, m;

	s = as;
	m = 1;
	if (*s == '-') {
		m = -1;
		s++;
	}
	for (n = 0; digit(*s); s++)
		n = (n*10) + (*s-'0');
	if (*s) {
		prs(as);
		err(": bad number");
	}
	return(n*m);
}

int
dobreak(t)
struct op *t;
{
	return(brkcontin(t->words[1], 1));
}

int
docontinue(t)
struct op *t;
{
	static int last;
	if(last){
		myfreearea(last);
	}
	loop_last_areanum = areanum;
	last = areanum;
	if (loop_is_called && areanum  >= FREE) {
		loop_last_areanum = last;
		areanum = loop_is_called ;
	}
	return(brkcontin(t->words[1], 0));
}

static int
brkcontin(cp, val)
register char *cp;
int val;
{
	register struct brkcon *bc;
	register int nl;

	nl = cp == NULL? 1: getn(cp);
	if (nl <= 0)
		nl = 999;
	do {
		if ((bc = brklist) == NULL)
			break;
		brklist = bc->nextlev;
	} while (--nl);
	if (nl) {
		err("bad break/continue level");
		return(1);
	}
	isbreak = val;
	longjmp(bc->brkpt, 1);
	/* NOTREACHED */
}

int
doexit(t)
struct op *t;
{
	register char *cp;

	execflg = 0;
	if ((cp = t->words[1]) != NULL)
		setstatus(getn(cp));
	leave();
	/* NOTREACHED */
}

int
doexport(t)
struct op *t;
{
	rdexp(t->words+1, export, EXPORT);
	return(0);
}

int
doreadonly(t)
struct op *t;
{
	rdexp(t->words+1, ronly, RONLY);
	return(0);
}

static void
rdexp(wp, f, key)
register char **wp;
void (*f)();
int key;
{
	if (*wp != NULL) {
		for (; *wp != NULL; wp++)
			if (checkname(*wp))
				(*f)(lookup(*wp));
			else
				badid(*wp);
	} else
		putvlist(key, 1);
}

static void
badid(s)
register char *s;
{
	prs(s);
	err(": bad identifier");
}

int
doset(t)
register struct op *t;
{
	register struct var *vp;
	register char *cp;
	register int n;
	if ((cp = t->words[1]) == NULL) {
		for (vp = vlist; vp; vp = vp->next)
			varput(vp->name, 1);
		return(0);
	}
	if (*cp == '-') {
		/* bad: t->words++; */
		for(n = 0; (t->words[n]=t->words[n+1]) != NULL; n++)
			;
		if (*++cp == 0)
			flag['x'] = flag['v'] = 0;
		else
			for (; *cp; cp++)
				switch (*cp) {
				case 'e':
					if (!talking)
						flag['e']++;
					break;

				default:
					if (*cp>='a' && *cp<='z')
						flag[(int) *cp]++;
					break;
				}
		setdash();
	}
	if (t->words[1]) {
		t->words[0] = dolv[0];
		for (n=1; t->words[n]; n++)
			setarea((char *)t->words[n], 0);
		/* DELETE old dolv 
		 * dolv points to environment variables when new shell starts,
		 * when "set" is called with arguments, we need to make sure 
		 * this call is not the first one. The second and following calls 
		 * should DELETE the old dolv[]
		 */
		{
		    int i = 1;
		    if (set_is_called){
			while(dolv[i]) {
				DELETE(dolv[i]);
				i++;
			}
			DELETE((dolv-1)); /* remove []: see setarea((char *)(dolv-1), 0); */
		    }
		}

		dolc = n-1;
		dolv = t->words;
		set_is_called = 1;
		setval(lookup("#"), putn(dolc));  /* wmq: set the number of arguments */
		setarea((char *)(dolv-1), 0);
	}
	return(0);
}

void
varput(s, out)
register char *s;
int out;
{
	if (letnum(*s)) {
		write(out, s, strlen(s));
		write(out, "\n", 1);
	}
}


#define	SECS	60L
#define	MINS	3600L

int
dotimes()
{
	struct tms tbuf;

	times(&tbuf);

	prn((int)(tbuf.tms_cutime / MINS));
	prs("m");
	prn((int)((tbuf.tms_cutime % MINS) / SECS));
	prs("s ");
	prn((int)(tbuf.tms_cstime / MINS));
	prs("m");
	prn((int)((tbuf.tms_cstime % MINS) / SECS));
	prs("s\n");
	return(0);
}

struct	builtin {
	char	*command;
	int	(*fn)();
};
static struct	builtin	builtin[] = {
	{":",		dolabel},
	{"cd",		dochdir},
	{"shift",	doshift},
	{"exec",	doexec},
	{"wait",	dowait},
	{"read",	doread},
	{"eval",	doeval},
	{"trap",	dotrap},
	{"break",	dobreak},
	{"continue",	docontinue},
	{"exit",	doexit},
	{"export",	doexport},
	{"readonly",	doreadonly},
	{"set",		doset},
	{".",		dodot},
	{"umask",	doumask},
	{"login",	dologin},
	{"newgrp",	dologin},
	{"times",	dotimes},
	{ NULL, 0},
};

int (*inbuilt(s))()
register char *s;
{
	register struct builtin *bp;

	for (bp = builtin; bp->command != NULL; bp++)
		if (strcmp(bp->command, s) == 0)
			return(bp->fn);
	return((int(*)())NULL);
}

