/* cgivars.c
 * (C) Copyright 2000, Moreton Bay (http://www.moretonbay.com).
 * see HTTP (www.w3.org) and RFC
 */
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cgivars.h"

/* local function prototypes */
char hex2char(char *hex);
void unescape_url(char *url);
char x2c(char *what);

/* hex2char */
/* RFC */
char hex2char(char *hex) {
	char char_value;
	char_value = (hex[0] >= 'A' ? ((hex[0] & 0xdf) - 'A') + 10 : (hex[0] - '0'));
	char_value *= 16;
	char_value += (hex[1] >= 'A' ? ((hex[1] & 0xdf) - 'A') + 10 : (hex[1] - '0'));
	return char_value;
}

/* unescape_url */
/* RFC */
void unescape_url(char *url) {
	int n, k;
	for(n=0, k=0;url[k];++n, ++k) {
		if((url[n] = url[k]) == '%') {
			url[n] = hex2char(&url[k+1]);
			k += 2;
		}
	}
	url[n] = '\0';
}


/* getRequestMethod
 * retn:	from_method (GET or POST) on success,
 *			-1 on failure.  */
int getRequestMethod() {
	char *request_method;
	int form_method;

	request_method = getenv("REQUEST_METHOD");
	if(request_method == NULL)
		return -1;

	if (!strcmp(request_method, "GET") || !strcmp(request_method, "HEAD") ) {
		form_method = GET;
	} else if (!strcmp(request_method, "POST")) {
		form_method = POST;
	} else {
		/* wtf was it then?!! */
		return -1;
	}
	return form_method;
}


/* getGETvars
 * retn:	getvars */
char **getGETvars() {
	int i;
	char **getvars;
	char *getinput;
	char **pairlist;
	int paircount = 0;
	char *nvpair;
	char *eqpos;

	getinput = getenv("QUERY_STRING");
	if (getinput)
		getinput = strdup(getinput);

	/* Change all plusses back to spaces */
   	for(i=0; getinput && getinput[i]; i++)
		if(getinput[i] == '+')
			getinput[i] = ' ';

   	pairlist = (char **) malloc(256*sizeof(char **));
	paircount = 0;
   	nvpair = getinput ? strtok(getinput, "&") : NULL;
	while (nvpair) {
		pairlist[paircount++]= strdup(nvpair);
        	if(!(paircount%256))
			pairlist = (char **) realloc(pairlist,(paircount+256)*sizeof(char **));
       		nvpair = strtok(NULL, "&");
	}

   	pairlist[paircount] = 0;
   	getvars = (char **) malloc((paircount*2+1)*sizeof(char **));
	for (i= 0; i<paircount; i++) {
		if(eqpos=strchr(pairlist[i], '=')) {
       	    		*eqpos = '\0';
            		unescape_url(getvars[i*2+1] = strdup(eqpos+1));
   	    	} else {
			unescape_url(getvars[i*2+1] = strdup(""));
        	}
		unescape_url(getvars[i*2] = strdup(pairlist[i]));
    	}
   	getvars[paircount*2] = 0;
    	for(i=0;pairlist[i];i++)
		free(pairlist[i]);
	free(pairlist);
	if (getinput)
		free(getinput);
	return getvars;
}


/* getPOSTvars
 * retn:	postvars */
char **getPOSTvars() {
	int i;
	int content_length;
	char **postvars;
	char *postinput;
	char **pairlist;
	int paircount = 0;
	char *nvpair;
	char *eqpos;
	
	postinput = getenv("CONTENT_LENGTH");
	if (!postinput)
		exit(1);
	if(!(content_length = atoi(postinput)))
		exit(1);
	if(!(postinput = (char *) malloc(content_length+1)))
		exit(1);
	if (!fread(postinput, content_length, 1, stdin))
		exit(1);
	postinput[content_length] = '\0';
	

   	for(i=0;postinput[i];i++)
		if(postinput[i] == '+')
			postinput[i] = ' ';

	pairlist = (char **) malloc(256*sizeof(char **));
	paircount = 0;
	nvpair = strtok(postinput, "&");
	while (nvpair) {
		pairlist[paircount++] = strdup(nvpair);
		if(!(paircount%256))
    			pairlist = (char **) realloc(pairlist, (paircount+256)*sizeof(char **));
		nvpair = strtok(NULL, "&");
	}
    
	pairlist[paircount] = 0;
	postvars = (char **) malloc((paircount*2+1)*sizeof(char **));
	for(i = 0;i<paircount;i++) {
        	if(eqpos = strchr(pairlist[i], '=')) {
       	    		*eqpos= '\0';
	        	unescape_url(postvars[i*2+1] = strdup(eqpos+1));
        	} else {
       	    		unescape_url(postvars[i*2+1] = strdup(""));
	   	}
        	unescape_url(postvars[i*2]= strdup(pairlist[i]));
	}
	postvars[paircount*2] = 0;

	for(i=0;pairlist[i];i++)
		free(pairlist[i]);
	free(pairlist);
	free(postinput);

	return postvars;
}

/* cleanUp
 * free the mallocs */
int cleanUp(int form_method, char **getvars, char **postvars) {
	int i;

	if (postvars) {
		for(i=0;postvars[i];i++)
			free(postvars[i]);
		free(postvars);
	}
	if (getvars) {
		for(i=0;getvars[i];i++)
			free(getvars[i]);
		free(getvars);
	}

	return 0;
}
