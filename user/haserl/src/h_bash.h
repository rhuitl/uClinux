/*
 * $Id: haserl.h,v 1.14 2005/11/18 14:43:10 nangel Exp $
 */
#ifndef H_SUBSHELL_H
#define H_SUBSHELL_H      1


/* the "names" for the pipes to the subshell */
enum pipe_t { PARENT_IN, PARENT_OUT };

/* h_bash.c */
void bash_destroy(void);
void bash_exec(buffer_t *buf, char *str);
void bash_wait(buffer_t *buf, char *str);
void bash_echo(buffer_t *buf, char *str, size_t len);
void bash_eval(buffer_t *buf, char *str, size_t len);
void bash_setup(char *shell, list_t *env);
void bash_doscript(buffer_t *script, char *name);



#endif /* !H_SUBSHELL_H */
