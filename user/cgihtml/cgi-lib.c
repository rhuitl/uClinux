/* cgi-lib.c - C routines that make writing CGI scripts in C a breeze
   Eugene Kim, <eekim@eekim.com>
   $Id: cgi-lib.c,v 1.13 1997/02/03 06:39:21 eekim Exp $
   Motivation: Perl is a much more convenient language to use when
     writing CGI scripts.  Unfortunately, it is also a larger drain on
     the system.  Hopefully, these routines will make writing CGI
     scripts just as easy in C.

   Copyright (C) 1996,1997 Eugene Eric Kim
   All Rights Reserved
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef WINDOWS
#include <io.h>
#endif

#include "cgi-lib.h"
#include "html-lib.h"
#include "string-lib.h"

/* symbol table for CGI encoding */
#define _NAME 0
#define _VALUE 1

short accept_image()
{
  char *httpaccept = getenv("HTTP_ACCEPT");

  if (strstr(httpaccept,"image") == NULL)
    return 0;
  else
    return 1;
}

/* x2c() and unescape_url() stolen from NCSA code */
char x2c(char *what)
{
  register char digit;

  digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
  digit *= 16;
  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
  return(digit);
}

void unescape_url(char *url)
{
  register int x,y;

  for (x=0,y=0; url[y]; ++x,++y) {
    if((url[x] = url[y]) == '%') {
      url[x] = x2c(&url[y+1]);
      y+=2;
    }
  }
  url[x] = '\0';
}

char *get_DEBUG()
{
  int bufsize = 1024;
  char *buffer = malloc(sizeof(char) * bufsize + 1);
  int i = 0;
  char ch;

  fprintf(stderr,"\n--- cgihtml Interactive Mode ---\n");
  fprintf(stderr,"Enter CGI input string.  Remember to encode appropriate ");
  fprintf(stderr,"characters.\nPress ENTER when done:\n\n");
  while ( (i<=bufsize) && ((ch = getc(stdin)) != '\n') ) {
    buffer[i] = ch;
    i++;
    if (i>bufsize) {
      bufsize *= 2;
      buffer = realloc(buffer,bufsize);
    }
  }
  buffer[i] = '\0';
  fprintf(stderr,"\n Input string: %s\nString length: %d\n",buffer,i);
  fprintf(stderr,"--- end cgihtml Interactive Mode ---\n\n");
  return buffer;
}

char *get_POST()
{
  int content_length;
  char *buffer;

  if (CONTENT_LENGTH != NULL) {
    content_length = atoi(CONTENT_LENGTH);
    buffer = malloc(sizeof(char) * content_length + 1);
    if (fread(buffer,sizeof(char),content_length,stdin) != content_length) {
      /* consistency error. */
      fprintf(stderr,"caught by cgihtml: input length < CONTENT_LENGTH\n");
      exit(1);
    }
    buffer[content_length] = '\0';
  }
  else { /* null content length */
    /* again, perhaps more detailed, robust error message here */
    fprintf(stderr,"caught by cgihtml: CONTENT_LENGTH is null\n");
    exit(1);
  }
  return buffer;
}

char *get_GET()
{
  char *buffer;

  if (QUERY_STRING == NULL) {
    fprintf(stderr,"caught by cgihtml: QUERY_STRING is null\n");
    exit(1);
  }
  buffer = newstr(QUERY_STRING);
  return buffer;
}

int parse_CGI_encoded(llist *entries, char *buffer)
{
  int i, j, num, token;
  int len = strlen(buffer);
  char *lexeme = malloc(sizeof(char) * len + 1);
  entrytype entry;
  node *window;

  list_create(entries);
  window = entries->head;
  i = 0;
  num = 0;
  token = _NAME;
  while (i < len) {
    j = 0;
    while ( (buffer[i] != '=') && (buffer[i] != '&') && (i < len) ) {
      lexeme[j] = (buffer[i] == '+') ? ' ' : buffer[i];
      i++;
      j++;
    }
    lexeme[j] = '\0';
    if (token == _NAME) {
      entry.name = newstr(lexeme);
      unescape_url(entry.name);
      if ( (buffer[i] != '=') || (i == len - 1) ) {
	entry.value = malloc(sizeof(char));
	strcpy(entry.value,"");
	window = list_insafter(entries, window, entry);
	free(lexeme);
	free(entry.name);
	free(entry.value);
	if (i == len - 1) /* null value at end of expression */
	  num++;
	else /* error in expression */
	  return -1;
      }
      else
	token = _VALUE;
    }
    else {
      entry.value = newstr(lexeme);
      unescape_url(entry.value);
      window = list_insafter(entries, window, entry);
      free(entry.name);
      free(entry.value);
      token = _NAME;
      num++;
    }
    i++;
    j = 0;
  }
  free(lexeme);
  return num;
}

/* stolen from k&r and seriously modified to do what I want */

int getline(char s[], int lim)
{
  int c, i=0, num;

  for (i=0; (i<lim) && ((c=getchar())!=EOF) && (c!='\n'); i++) {
    s[i] = c;
  }
  if (c == '\n') {
    s[i] = c;
  }
  if ((i==0) && (c!='\n'))
    num = 0;
  else if (i == lim)
    num = i;
  else
    num = i+1;
  return num;
}

int parse_form_encoded(llist* entries)
{
  long content_length;
  entrytype entry;
  node* window;
  FILE *uploadfile;
  char *uploadfname, *tempstr, *boundary;
  char *buffer = malloc(sizeof(char) * BUFSIZ + 1);
  char *prevbuf = malloc(sizeof(char) + BUFSIZ + 1);
  short isfile,done,start,winbrowser;
  int i,j;
  int bytesread,prevbytesread;
  int buffersize = BUFSIZ;
  int numentries = 0;

#ifdef WINDOWS
  setmode(fileno(stdin), O_BINARY);   /* define stdin as binary */
  _fmode = BINARY;                    /* default all file I/O as binary */
#endif
  if (CONTENT_LENGTH != NULL)
    content_length = atol(CONTENT_LENGTH);
  else
    return 0;
  /* get boundary */
  tempstr = newstr(CONTENT_TYPE);
  boundary = strstr(tempstr,"boundary=");
  boundary += (sizeof(char) * 9);
  /* create list */
  list_create(entries);
  window = entries->head;
  /* ignore first boundary; this isn't so robust; improve it later */
  getline(buffer,BUFSIZ);
  /* now start parsing */
  while ((bytesread=getline(buffer,BUFSIZ)) != 0) {
    start = 1;
    /* this assumes that buffer contains no binary characters.
       if the buffer contains the first valid header, then this
       is a safe assumption.  however, it should be improved for
       robustness sake. */
    buffer[bytesread] = '\0';
    tempstr = newstr(buffer);
    tempstr += (sizeof(char) * 38); /* 38 is header up to name */
    entry.name = tempstr;
    entry.value = malloc(sizeof(char) * BUFSIZ + 1);
    strcpy(entry.value,"");
    while (*tempstr != '"')
      tempstr++;
    *tempstr = '\0';
    if (strstr(buffer,"filename=\"") != NULL) {
      isfile = 1;
      tempstr = newstr(buffer);
      tempstr = strstr(tempstr,"filename=\"");
      tempstr += (sizeof(char) * 10);
      if (strlen(tempstr) >= BUFSIZ)
	entry.value = realloc(entry.value,sizeof(char) * strlen(tempstr)+1);
      entry.value = tempstr;
      while (*tempstr != '"')
	tempstr++;
      *tempstr = '\0';
      /* Netscape's Windows browsers handle paths differently from its
	 UNIX and Mac browsers.  It delivers a full path for the uploaded
	 file (which it shouldn't do), and it uses backslashes rather than
	 forward slashes.  No need to worry about Internet Explorer, since
	 it doesn't support HTTP File Upload at all. */
      if (strstr(lower_case(HTTP_USER_AGENT),"win") != 0) {  
	winbrowser = 1;
        tempstr = strrchr(entry.value, '\\');
	tempstr++;
	entry.value = tempstr;
      }
      else
	winbrowser = 0;
      window = list_insafter(entries,window,entry);
      numentries++;
      uploadfname = malloc(strlen(UPLOADDIR) + strlen(entry.value) + 2);
      if (winbrowser)
	sprintf(uploadfname,"%s\\%s",UPLOADDIR,entry.value);
      else
	sprintf(uploadfname,"%s/%s",UPLOADDIR,entry.value);
      if ( (uploadfile = fopen(uploadfname,"w")) == NULL) {
	fprintf(stderr,"cgihtml Error: cannot upload file\n");
	exit(1);
      }
    }
    else
      isfile = 0;
    /* ignore rest of headers and first blank line */
    while (getline(buffer, BUFSIZ) > 1) {
      /* DOS style blank line? */
      if ((buffer[0] == '\r') && (buffer[1] == '\n'))
	break;
    }
    done = 0;
    j = 0;
    while (!done) {
      bytesread = getline(buffer,BUFSIZ);
      buffer[bytesread] = '\0';
      if (strstr(buffer,boundary) == NULL) {
	if (start) {
	  i = 0;
	  while (i < bytesread) {
	    prevbuf[i] = buffer[i];
	    i++;
	  }
	  prevbytesread = bytesread;
	  start = 0;
	}
	else {
	  /* flush buffer */
	  i = 0;
	  while (i < prevbytesread) {
	    if (isfile)
	      fputc(prevbuf[i],uploadfile);
	    else {
	      if (j > buffersize) {
		buffersize += BUFSIZ;
		entry.value = realloc(entry.value,sizeof(char)*buffersize+1);
	      }
	      entry.value[j] = prevbuf[i];
	      j++;
	    }
	    i++;
	  }
	  /* buffer new input */
	  i = 0;
	  while (i < bytesread) {
	    prevbuf[i] = buffer[i];
	    i++;
	  }
	  prevbytesread = bytesread;
	}
      }
      else {
	done = 1;
	/* flush buffer except last two characters */
	i = 0;
	while (i < prevbytesread - 2) {
	  if (isfile)
	    fputc(prevbuf[i],uploadfile);
	  else {
	    if (j > buffersize) {
	      buffersize += BUFSIZ;
	      entry.value = realloc(entry.value,sizeof(char)*buffersize+1);
	    }
	    entry.value[j] = prevbuf[i];
	    j++;
	  }
	  i++;
	}
      }
    }
    if (isfile)
      fclose(uploadfile);
    else {
      window = list_insafter(entries,window,entry);
      numentries++;
      j = 0;
    }
  }
  return numentries;
}

int read_cgi_input(llist* entries)
{
  char *input;

  /* check for form upload.  this needs to be first, because the
     standard way of checking for POST data is inadequate.  If you
     are uploading a 100 MB file, you are unlikely to have a buffer
     in memory large enough to store the raw data for parsing.
     Instead, parse_form_encoded parses stdin directly.

     In the future, I may modify parse_CGI_encoded so that it also
     parses POST directly from stdin.  I'm undecided on this issue,
     because doing so will make parse_CGI_encoded less general. */
  if ((CONTENT_TYPE != NULL) &&
      (strstr(CONTENT_TYPE,"multipart/form-data") != NULL) )
    return parse_form_encoded(entries);

  /* get the input */
  if (REQUEST_METHOD == NULL)
    input = get_DEBUG();
  else if (!strcmp(REQUEST_METHOD,"POST"))
    input = get_POST();
  else if (!strcmp(REQUEST_METHOD,"GET"))
    input = get_GET();
  else { /* error: invalid request method */
    fprintf(stderr,"caught by cgihtml: REQUEST_METHOD invalid\n");
    exit(1);
  }
  /* parse the input */
  return parse_CGI_encoded(entries,input);
}

char *cgi_val(llist l, char *name)
{
  short FOUND = 0;
  node* window;

  window = l.head;
  while ( (window != 0) && (!FOUND) )
    if (!strcmp(window->entry.name,name))
      FOUND = 1;
    else
      window = window->next;
  if (FOUND)
    return window->entry.value;
  else
    return NULL;
}

/* cgi_val_multi - contributed by Mitch Garnaat <garnaat@wrc.xerox.com>;
   modified by me */

char **cgi_val_multi(llist l, char *name)
{
  short FOUND = 0;
  node* window;
  char **ret_val = 0;
  int num_vals = 0, i;

  window = l.head;
  while (window != 0) {
    if (!strcmp(window->entry.name,name)) {
      FOUND = 1;
      num_vals++;
    }
    window = window->next;
  }
  if (FOUND) {
    /* copy the value pointers into the returned array */
    ret_val = (char**) malloc(sizeof(char*) * (num_vals + 1));
    window = l.head;
    i = 0;
    while (window != NULL) {
      if (!strcmp(window->entry.name,name)) {
	ret_val[i] = window->entry.value;
	i++;
      }
      window = window->next;
    }
    /* NULL terminate the array */
    ret_val[i] = 0;
    return ret_val;
  }
  else
    return NULL;
}

char *cgi_name(llist l, char *value)
{
  short FOUND = 0;
  node* window;

  window = l.head;
  while ( (window != 0) && (!FOUND) )
    if (!strcmp(window->entry.value,value))
      FOUND = 1;
    else
      window = window->next;
  if (FOUND)
    return window->entry.name;
  else
    return NULL;
}

char **cgi_name_multi(llist l, char *value)
{
  short FOUND = 0;
  node* window;
  char **ret_val = 0;
  int num_vals = 0, i;

  window = l.head;
  while (window != 0) {
    if (!strcmp(window->entry.value,value)) {
      FOUND = 1;
      num_vals++;
    }
    window = window->next;
  }
  if (FOUND) {
    /* copy the value pointers into the returned array */
    ret_val = (char**) malloc(sizeof(char*) * (num_vals + 1));
    window = l.head;
    i = 0;
    while (window != NULL) {
      if (!strcmp(window->entry.value,value)) {
	ret_val[i] = window->entry.name;
	i++;
      }
      window = window->next;
    }
    /* NULL terminate the array */
    ret_val[i] = 0;
    return ret_val;
  }
  else
    return NULL;
}

/* miscellaneous useful CGI routines */

int parse_cookies(llist *entries)
{
  char *cookies = getenv("HTTP_COOKIE");
  node* window;
  entrytype entry;
  int i,len;
  int j = 0;
  int numcookies = 0;
  short NM = 1;

  if (cookies == NULL)
    return 0;
  list_create(entries);
  window = entries->head;
  len = strlen(cookies);
  entry.name = malloc(sizeof(char) * len + 1);
  entry.value = malloc(sizeof(char) * len + 1);
  for (i = 0; i < len; i++) {
    if (cookies[i] == '=') {
      entry.name[j] = '\0';
      if (i == len - 1) {
	strcpy(entry.value,"");
	window = list_insafter(entries,window,entry);
	numcookies++;
      }
      j = 0;
      NM = 0;
    }
      else if ( (cookies[i] == '&') || (i == len - 1) ) {
	if (!NM) {
	  if (i == len - 1) {
	    entry.value[j] = cookies[i];
	    j++;
	  }
	  entry.value[j] = '\0';
	  window = list_insafter(entries,window,entry);
	  numcookies++;
	  j = 0;
	  NM = 1;
	}
      }
    else if ( (cookies[i] == ';') || (i == len - 1) ) {
      if (!NM) {
	if (i == len - 1) {
	  entry.value[j] = cookies[i];
	  j++;
	}
	entry.value[j] = '\0';
	window = list_insafter(entries,window,entry);
	numcookies++;
	i++;   /* erases trailing space */
	j = 0;
	NM = 1;
      }
    }
    else if (NM) {
      entry.name[j] = cookies[i];
      j++;
    }
    else if (!NM) {
      entry.value[j] = cookies[i];
      j++;
    }
  }
  return numcookies;
}

void print_cgi_env()
{
  if (SERVER_SOFTWARE != NULL)
    printf("<p>SERVER_SOFTWARE = %s<br>\n",SERVER_SOFTWARE);
  if (SERVER_NAME != NULL)
    printf("SERVER_NAME = %s<br>\n",SERVER_NAME);
  if (GATEWAY_INTERFACE !=NULL)
    printf("GATEWAY_INTERFACE = %s<br>\n",GATEWAY_INTERFACE);

  if (SERVER_PROTOCOL != NULL)
    printf("SERVER_PROTOCOL = %s<br>\n",SERVER_PROTOCOL);
  if (SERVER_PORT != NULL)
    printf("SERVER_PORT = %s<br>\n",SERVER_PORT);
  if (REQUEST_METHOD != NULL)
    printf("REQUEST_METHOD = %s<br>\n",REQUEST_METHOD);
  if (PATH_INFO != NULL)
    printf("PATH_INFO = %s<br>\n",PATH_INFO);
  if (PATH_TRANSLATED != NULL)
    printf("PATH_TRANSLATED = %s<br>\n",PATH_TRANSLATED);
  if (SCRIPT_NAME != NULL)
    printf("SCRIPT_NAME = %s<br>\n",SCRIPT_NAME);
  if (QUERY_STRING != NULL)
    printf("QUERY_STRING = %s<br>\n",QUERY_STRING);
  if (REMOTE_HOST != NULL)
    printf("REMOTE_HOST = %s<br>\n",REMOTE_HOST);
  if (REMOTE_ADDR != NULL)
    printf("REMOTE_ADDR = %s<br>\n",REMOTE_ADDR);
  if (AUTH_TYPE != NULL)
    printf("AUTH_TYPE = %s<br>\n",AUTH_TYPE);
  if (REMOTE_USER != NULL)
    printf("REMOTE_USER = %s<br>\n",REMOTE_USER);
  if (REMOTE_IDENT != NULL)
    printf("REMOTE_IDENT = %s<br>\n",REMOTE_IDENT);
  if (CONTENT_TYPE != NULL)
    printf("CONTENT_TYPE = %s<br>\n",CONTENT_TYPE);
  if (CONTENT_LENGTH != NULL)
    printf("CONTENT_LENGTH = %s<br></p>\n",CONTENT_LENGTH);

  if (HTTP_USER_AGENT != NULL)
    printf("HTTP_USER_AGENT = %s<br></p>\n",HTTP_USER_AGENT);
}

void print_entries(llist l)
{
  node* window;

  window = l.head;
  printf("<dl>\n");
  while (window != NULL) {
    printf("  <dt> <b>%s</b>\n",window->entry.name);
    printf("  <dd> %s\n",replace_ltgt(window->entry.value));
    window = window->next;
  }
  printf("</dl>\n");
}

char *escape_input(char *str)
/* takes string and escapes all metacharacters.  should be used before
   including string in system() or similar call. */
{
  int i,j = 0;
  char *new = malloc(sizeof(char) * (strlen(str) * 2 + 1));

  for (i = 0; i < strlen(str); i++) {
    if (!( ((str[i] >= 'A') && (str[i] <= 'Z')) ||
	   ((str[i] >= 'a') && (str[i] <= 'z')) ||
	   ((str[i] >= '0') && (str[i] <= '9')) )) {
      new[j] = '\\';
      j++;
    }
    new[j] = str[i];
    j++;
  }
  new[j] = '\0';
  return new;
}

/* boolean functions */

short is_form_empty(llist l)
{
  node* window;
  short EMPTY = 1;

  window = l.head;
  while ( (window != NULL) && (EMPTY == 1) ) {
    if (strcmp(window->entry.value,""))
      EMPTY = 0;
    window = window->next;
  }
  return EMPTY;
}

short is_field_exists(llist l, char *str)
{
  if (cgi_val(l,str) == NULL)
    return 0;
  else
    return 1;
}

/* is_field_empty returns true either if the field exists but is empty
   or if the field does not exist. */
short is_field_empty(llist l, char *str)
{
  char *temp = cgi_val(l,str);

  if ( (temp == NULL) || (!strcmp(temp,"")) )
    return 1;
  else
    return 0;
}
