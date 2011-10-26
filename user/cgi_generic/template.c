/* template.c */

#include <stdio.h>

#include "cgivars.h"
#include "htmllib.h"


#define DEBUG		1

int template_page(char **postvars, int form_method) {
	int i;
	
	addTitleElement("Demo CGI");

	if(form_method == POST) {
		for (i=0; postvars[i]; i+= 2) {
#if DEBUG
			printf("<li>DEBUG: [%s] = [%s]\n", postvars[i], postvars[i+1]);
#endif
		}
	}

	/* GET */
	printf("<FORM ACTION=\"%s\" METHOD=POST>", "/cgi-bin/cgi_demo");
	printf("<SELECT NAME=\"port\">");
	printf("<OPTION>COM 1");
	printf("<OPTION>COM 2");
	printf("</SELECT>");
	printf("</TD></TR>");
	printf("<BR><INPUT TYPE=submit VALUE=\"Submit\">");
	printf("<INPUT TYPE=reset VALUE=\"Reset\">");
	printf("</FORM>");
			
	return 0;	
}


