#ifndef REGEX_COMPAT_H
#define REGEX_COMPAT_H
/*
 * regex_compat.h
 *
 *
 * Copyright (c) 2004 Snapgear
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 */

/* Compatibility wrapper for V8 regexp to emulate POSIX regex
 * Provides compatibility across a limited range of functionality
 */
#include <regexp.h>

typedef struct {
        regexp *preg;
} regex_t;

typedef struct {
        int rm_so;
        int rm_eo;
} regmatch_t;

#define REG_EXTENDED 0
#define REG_NOERROR  0      /* Success.  */
#define REG_NOMATCH  1      /* Didn't find a match (for regexec).  */
#define REG_BADPAT   2      /* Invalid pattern */
/* ... other errors > 2 ... */

int compat_regcomp(regex_t *preg, const char *regex, int cflags);
int compat_regexec(const  regex_t  *preg,  const  char *string, size_t nmatch,
regmatch_t pmatch[], int eflags);
size_t compat_regerror(int errcode, const regex_t *preg, char *errbuf,  size_t
errbuf_size);
void compat_regfree(regex_t *preg);

#ifndef REGEX_COMPAT_IMPL
#define regcomp compat_regcomp
#define regexec compat_regexec
#define regerror compat_regerror
#define regfree compat_regfree
#endif

#endif
