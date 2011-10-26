#ifndef TINYTCAP_H
#define TINYTCAP_H

int tgetent(char *bp, const char *name);
char *tgetstr(const char *attr, char **area);
int tputs(const char *str, int affcnt, int (*putc)(int));
char *tgoto(const char *cap, int col, int row);
int tgetnum(const char *attr);

#endif
