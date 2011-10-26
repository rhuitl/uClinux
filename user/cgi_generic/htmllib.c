/* htmllib.c
 * HTML common library functions for the CGI programs. */

#include <stdio.h>
#include "htmllib.h"


void htmlHeader(char *title) {
  printf("Content-type: text/html\n\n<HTML><HEAD><TITLE>%s</TITLE></HEAD>",
		  title);
}

void htmlBody() {
    printf("<BODY>");
}

void htmlFooter() {
    printf("</BODY></HTML>");
}

void addTitleElement(char *title) {
	printf("<H1>%s</H1>", title);
}
