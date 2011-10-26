/*	setbenv.c
 *	OZH, 2001-2005
 *      David Wu 2007 
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef CONFIG_LIB_LIBBSC
#include "bootstd.h"
#else
#include <asm/uCbootstrap.h>
_bsc1 (int, setbenv, char *, a)
#endif

#ifndef MAX_ENVNAME_SIZE
#define MAX_ENVNAME_SIZE        31
#endif
#ifndef MAX_ENVDATA_SIZE
#define MAX_ENVDATA_SIZE        1024
#endif

#define ENAME 2
#define EDATA 3

int main(int argc, char *argv[]) 
{
    /* 
     * Buffer length needs to support a 31 character variable name
     * an equal sign and a 1024 character value and terminator. 
     */
    char buf[MAX_ENVNAME_SIZE+1+MAX_ENVDATA_SIZE+1];

    if	(argc<2) {
	printf("usage: %s varname value\n       %s varname\n",argv[0],argv[0]);
	return 0; 
    }

    if  ( strchr(argv[1], '=') && argc > 2 ) {	/* variable name _MUST_NOT_ include '=' symbol	*/
        printf("%s: variable name must not include \"=\"\n", argv[0]);	
        return -1;
    }
    if	(argc>2) {
        if(strlen(argv[1]) > MAX_ENVNAME_SIZE) {
            printf("%s: variable name is longer than %d Bytes\n", argv[0], MAX_ENVNAME_SIZE);
            return ENAME;
        }
        if(strlen(argv[2]) > MAX_ENVDATA_SIZE) {
            printf("%s: value is longer than %d Bytes\n", argv[0], MAX_ENVDATA_SIZE);
            return EDATA;
        }
        strcpy(buf, argv[1]);
	strcat(buf, "=");
	strcat(buf, argv[2]); 
    } else {
        if(strlen(argv[1]) > sizeof(buf)) {
            /* printf("%s: %s is too large\n", argv[0], argv[1]); */
            return -1;
        }
        strcpy(buf, argv[1]);
    }
#ifdef CONFIG_LIB_LIBBSC
    return bsc_setenv(buf);
#else
    setbenv(buf);
    return (0); 
#endif
}
