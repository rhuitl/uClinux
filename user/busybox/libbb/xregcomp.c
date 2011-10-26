/* vi: set sw=4 ts=4: */
/*
 * Utility routines.
 *
 * Copyright (C) many different people.
 * If you wrote this, please acknowledge your work.
 *
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

#if defined(__UC_LIBC__USE_REGEXP_H__)

#include <regexp.h>

void xregcomp(regex_t *preg, const char *reg, int cflags)
{
	regexp *ret;
	const char *r;
	r = reg;
	if (cflags)
		bb_error_msg_and_die("xregcomp: no support for -i");
	ret = regcomp(r);
	if (ret == NULL) {
		regerror("cannot compile expression");
		exit(1);
	}
	*preg = ret;
}

#else

#include "xregex.h"

char* regcomp_or_errmsg(regex_t *preg, const char *regex, int cflags)
{
	int ret = regcomp(preg, regex, cflags);
	if (ret) {
		int errmsgsz = regerror(ret, preg, NULL, 0);
		char *errmsg = xmalloc(errmsgsz);
		regerror(ret, preg, errmsg, errmsgsz);
		return errmsg;
	}
	return NULL;
}

void xregcomp(regex_t *preg, const char *regex, int cflags)
{
	char *errmsg = regcomp_or_errmsg(preg, regex, cflags);
	if (errmsg) {
		bb_error_msg_and_die("xregcomp: %s", errmsg);
	}
}
#endif

/* END CODE */
/*
Local Variables:
c-file-style: "linux"
c-basic-offset: 4
tab-width: 4
End:
*/
