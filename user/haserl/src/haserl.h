#ifndef _HASERL_H
#define _HASERL_H	1


/* Just a silly construct to contain global variables    */
typedef struct
{
  unsigned long uploadkb;       /* how big an upload do we allow (0 for none) */
  char *shell;                  /* The shell we use                                     */
  char *uploaddir;              /* where we upload to                                   */
  char *uploadhandler;		/* a handler for uploads				*/
  char *var_prefix;		/* what name we give to FORM variables			*/
  char *nul_prefix;		/* what name we give to environment variables		*/
  token_t *uploadlist;		/* a linked list of pathspecs				*/
  int debug;                    /* true if in "debug" mode                              */
  int acceptall;                /* true if we'll accept POST data on GETs and vice versa */
  int silent;                   /* true if we never print errors                        */
} haserl_t;

extern haserl_t global;
	
char x2c(char *what);
void unescape_url(char *url);
void *xmalloc (size_t size);
void *xrealloc (void *buf, size_t size);
list_t *myputenv(list_t *cur, char *str, char *prefix);
void free_list_chain ( list_t *);
void readenv(list_t *env);
void CookieVars(list_t *env);
void sessionid(list_t *env);
list_t *wcversion(list_t *env);
void haserlflags(list_t *env);
int ReadCGIQueryString(list_t *env);
int ReadCGIPOSTValues(list_t *env);
int LineToStr(char *string, size_t max);
int ReadMimeEncodedInput(list_t *env);
void PrintParseError(char *error, int linenum);
int parseCommandLine(int argc, char *argv[]);
int BecomeUser(uid_t uid, gid_t gid);
void assignGlobalStartupValues(void);
void unlink_uploadlist (void);
int main(int argc, char *argv[]);


extern void (*shell_exec)(buffer_t *buf, char *str);
extern void (*shell_echo)(buffer_t *buf, char *str, size_t len);
extern void (*shell_eval)(buffer_t *buf, char *str, size_t len);
extern void (*shell_setup)( char *, list_t *);
extern void (*shell_doscript)( buffer_t *, char *);
extern void (*shell_destroy) (void);

#endif /* !_HASERL_H */


