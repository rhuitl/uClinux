
#include <stdlib.h>
#include <string.h>

#define	TMPDIR		"/var/tmp"
#define	TMPFILE		"XXXXXX"

char *tempnam(const char *dir, const char *pfx)
{
	static char nam[32];

	strcpy(nam, dir ? dir : TMPDIR);
	strcat(nam, "/");
	strcat(nam, pfx ? pfx : TMPFILE);
	if (mktemp(nam) == NULL)
		return(NULL);
	return(nam);
}

