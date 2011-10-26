/*
 * regex_compat.c
 *
 *
 * Copyright (c) 2004 Snapgear
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 */
#include <features.h>

#ifdef __UC_LIBC__
#include <stdio.h>
#define REGEX_COMPAT_IMPL
#include "regex_compat.h"

int compat_regcomp(regex_t *preg, const char *regex, int cflags)
{
        preg->preg = regcomp((char *)regex);
        return(preg->preg == 0);
}

int compat_regexec(const  regex_t  *preg,  const  char *string, size_t nmatch, regmatch_t pmatch[], int eflags)
{
        if (regexec(preg->preg, (char *)string) == 1) {
                int i;
                for (i = 0; i < NSUBEXP && i < nmatch; i++) {
                        if (preg->preg->startp[i]) {
                                pmatch[i].rm_so = preg->preg->startp[i] - string;
                        }
                        else {
                                pmatch[i].rm_so = -1;
                        }
                        if (preg->preg->endp[i]) {
                                pmatch[i].rm_eo = preg->preg->endp[i] - string;
                        }
                        else {
                                pmatch[i].rm_eo = -1;
                        }
                }
                return(0);
        }
        /* No match */
        return(1);
}

size_t compat_regerror(int errcode, const regex_t *preg, char *errbuf,  size_t errbuf_size)
{
        return snprintf(errbuf, errbuf_size, "regex_compat() error %d", errcode);
}

void compat_regfree(regex_t *preg)
{
}
#endif
