#include <security/pam_modules.h>

/* support.c */
extern int _pam_parse (int argc, const char **argv);
extern unsigned long _resolve_name (char *serv);
extern int tacacs_get_password (pam_handle_t * pamh, int flags
		     ,int ctrl, char **password);
extern int converse (pam_handle_t * pamh, int nargs
	  ,struct pam_message **message
	  ,struct pam_response **response);
extern void _pam_log (int err, const char *format,...);
extern void *_xcalloc (size_t size);
extern char *_pam_get_terminal(pam_handle_t *pamh);
