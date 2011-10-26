
/* Copyright (C) 2000 Lineo Australia */

#include <string.h>
#include <ctype.h>

char *strcasestr(str1, str2)
__const char *str1, *str2;
{
    const char *s1, *s2;
    char c1, c2, cs;
    int	len = strlen(str1) - strlen(str2) + 1;

    if ((cs = *str2) != '\0') {
	if (isupper(cs))
	    cs = _tolower(cs);
	for (; len > 0;	len--, str1++){
	    c1 = *str1;
	    if (isupper(c1))
		c1 = _tolower(c1);
	    if (c1 != cs)
		continue;

	    for	(s1 = str1, s2 = str2; *s2 != '\0'; s1++, s2++) {
		c1 = *s1;
		if (isupper(c1))
		    c1 = _tolower(c1);
		c2 = *s2;
		if (isupper(c2))
		    c2 = _tolower(c2);
		if (c1 != c2)
		    break;
	    }

	    if (*s2 == '\0')
		return (char*) str1;
	}
    }
    return (char*)0;
}
