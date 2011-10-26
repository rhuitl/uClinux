#include <string.h>
#include <stdio.h>

#include "tinytcap.h"

int tgetent(char *bp, const char *name)
{
	return(1);
}

char *tgetstr(const char *attr, char **area)
{
	if (strcmp(attr, "cm") == 0) {
		// Terminal Crusor motion ESC sequence
		return("\033[%d;%dH");
	}
	if (strcmp(attr, "cd") == 0) {
		// Clear from cursor to end of screen
		return("\033[0J");
	}
	if (strcmp(attr, "cl") == 0) {
		// Clear screen and home
		return("\033[H\033[2J");
	}
	if (strcmp(attr, "ce") == 0) {
		// Clear from cursor to end of line
		return("\033[0K");
	}
	if (strcmp(attr, "ho") == 0) {
		// Clear from cursor to end of line
		return("\033[H");
	}
	if (strcmp(attr, "md") == 0) {
		// Terminal standout mode on
		return("\033[1m");
	}
	if (strcmp(attr, "mr") == 0) {
		// Terminal reverse mode on
		return("\033[7m");
	}
	if (strcmp(attr, "me") == 0) {
		// Terminal standout mode off
		return("\033[0m");
	}
#if 0
	CMup= "\033[A";		// move cursor up one line, same col
	CMdown="\n";		// move cursor down one line, same col
	bell= "\007";		// Terminal bell sequence
#endif
	return(0);
}

int tputs(const char *str, int affcnt, int (*putter)(int))
{
	if (!str) {
		return(1);
	}

	while (*str) {
		putter(*str);
		str++;
	}
	return(1);
}

char *tgoto(const char *cap, int col, int row)
{
	static char buf[30];

	snprintf(buf, sizeof(buf), cap, row + 1, col + 1);

	return(buf);
}

int tgetnum(const char *attr)
{
	if (strcmp(attr, "co") == 0) {
		return(80);
	}
	if (strcmp(attr, "li") == 0) {
		return(25);
	}
	return(-1);
}
