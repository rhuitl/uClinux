#ifndef __CFGFILE_H__
#define __CFGFILE_H__

#include <stdio.h>
char ** cfgread(FILE *fp);
char ** cfgfind(FILE *fp, char *var);

#endif /* __CFGFILE_H__ */
