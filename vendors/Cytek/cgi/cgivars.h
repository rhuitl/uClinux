/* cgivars.h */

#ifndef _CGIVARS_H
#define _CGIVARS_H

/* method */
#define GET	0
#define POST	1


/* function prototypes */
int getRequestMethod();
char **getGETvars();
char **getPOSTvars();
int cleanUp(int form_method, char **getvars, char **postvars);


#endif	/* !_CGIVARS_H */
