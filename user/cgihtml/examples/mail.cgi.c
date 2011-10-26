/* mail.cgi.c - CGI program that parses comments form, and mails it to
      appropriate user
   Eugene Kim, eekim@fas.harvard.edu
   $Id: mail.cgi.c,v 1.6 1996/10/24 06:54:10 eekim Exp $

   Copyright (C) 1996 Eugene Eric Kim
   All Rights Reserved
*/

#include <stdio.h>
#include <string.h>
#include "cgi-lib.h"
#include "html-lib.h"
#include "string-lib.h"

/*
   Edit these two defines.  Make sure you create a mail.conf file in
   a directory of your choice.  Format for mail.conf is a complete
   e-mail address on each line.  A minimal mail.conf file should
   contain the value of WEBADMIN.  For example, if WEBADMIN is
   web@somewhere.edu, your mail.conf file should contain one line:
       web@somewhere.edu
*/
#define WEBADMIN "web@somewhere.edu"
#define AUTH "/usr/local/etc/httpd/conf/mail.conf"

void NullForm()
{
  html_begin("Null Form Submitted");
  h1("Null Form Submitted");
  printf("You have sent an empty form.  Please go back and fill out\r\n");
  printf("the form properly, or email <i>%s</i>\r\n",WEBADMIN);
  printf("if you are having difficulty.\r\n");
  html_end();
}

void authenticate(char *dest)
{
  FILE *access;
  char s[80];
  short FOUND = 0;

  access = fopen(AUTH,"r");
  while ( (fgets(s,80,access)!=NULL) && (!FOUND) ) {
    s[strlen(s) - 1] = '\0';
    if (!strcmp(s,dest))
      FOUND = 1;
  }
  if (!FOUND) {
    /* not authenticated */
    html_begin("Unauthorized Destination");
    h1("Unauthorized Destination");

    html_end();
    exit(1);
  }
}

int main()
{
  llist entries;
  FILE *mail;
  char command[256] = "/usr/lib/sendmail ";
  char *dest,*name,*email,*subject,*content;

  html_header();
  read_cgi_input(&entries);
  if ( !strcmp("",cgi_val(entries,"name")) &&
      !strcmp("",cgi_val(entries,"email")) &&
      !strcmp("",cgi_val(entries,"subject")) &&
      !strcmp("",cgi_val(entries,"content")) )
    NullForm();
  else {
    if (is_field_empty(entries,"to"))
      dest = newstr(WEBADMIN);
    else
      dest = newstr(cgi_val(entries,"to"));
    name = newstr(cgi_val(entries,"name"));
    email = newstr(cgi_val(entries,"email"));
    subject = newstr(cgi_val(entries,"subject"));
    if (dest[0]=='\0')
      strcpy(dest,WEBADMIN);
    else
      authenticate(dest);
    /* no need to escape_input() on dest, since we assume there aren't
       insecure entries in the authentication file. */
    strcat(command,dest);
    mail = popen(command,"w");
    if (mail == NULL) {
      html_begin("System Error!");
      h1("System Error!");
      printf("Please mail %s and inform\r\n",WEBADMIN);
      printf("the web maintainers that the comments script is improperly\r\n");
      printf("configured. We apologize for the inconvenience<p>\r\n");
      printf("<hr>\r\nWeb page created on the fly by ");
      printf("<i>%s</i>.\r\n",WEBADMIN);
      html_end();
    }
    else {
      content = newstr(cgi_val(entries,"content"));
      fprintf(mail,"From: %s (%s)\n",email,name);
      fprintf(mail,"Subject: %s\n",subject);
      fprintf(mail,"To: %s\n",dest);
      fprintf(mail,"X-Sender: %s\n\n",WEBADMIN);
      fprintf(mail,"%s\n\n",content);
      pclose(mail);
      html_begin("Comment Submitted");
      h1("Comment Submitted");
      printf("You submitted the following comment:\r\n<pre>\r\n");
      printf("From: %s (%s)\r\n",email,name);
      printf("Subject: %s\r\n\r\n",subject);
      printf("%s\r\n</pre>\r\n",content);
      printf("Thanks again for your comments.<p>\r\n");
      printf("<hr>\r\nWeb page created on the fly by ");
      printf("<i>%s</i>.\r\n",WEBADMIN);
      html_end();
    }
  }
  list_clear(&entries);
  return 0;
}
