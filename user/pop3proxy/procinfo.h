
#ifndef _PROCINFO_INCLUDED
#define	_PROCINFO_INCLUDED


#include <stdarg.h>

#define	PROXYNAME	"pop3.proxy"


typedef struct _procinfo {
    int		mainpid;
    char	pidfile[200];

    char	statfile[200];
    FILE	*statfp;
    } procinfo_t;


extern char varprefix[40];
extern char statdir[200];
extern char sessiondir[200];

extern procinfo_t pi;


extern int init_procinfo(char *vp);
extern FILE *getstatfp(void);

extern int geterrcode(char *name);
extern int set_sessionmode(char *word, char *filename, int lineno);

char *set_exithandler(char *handler);
extern int set_exitcodes(int mask);

extern int setvar(char *name, char *value);
extern int setnumvar(char *name, unsigned long value);
extern int run_errorhandler(int error);

extern int printerror(int rc, char *type, char *format, ...);

char *setpidfile(char *pidfile);

void exithandler(void);

#endif

