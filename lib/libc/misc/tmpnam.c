
#include <stdlib.h>
#include <string.h>

#define	TMPFILE		"/var/tmp/XXXXXX"

char *tmpnam(char *s)
{
	static char nam[32];

	strcpy(nam, TMPFILE);
	if (mktemp(nam) == NULL)
		return(NULL);
	if (s) {
		strcpy(s, nam);
		return(s);
	}
	return(nam);
}

