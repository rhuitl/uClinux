/* httpd.c:  A very simple http server
 * Copyright (C) 2000  	   Lineo, Inc.  (www.lineo.com)
 * Copyright (c) 1997-1999 D. Jeff Dionne <jeff@lineo.ca>
 * Copyright (c) 1998      Kenneth Albanowski <kjahds@kjahds.com>
 * Copyright (c) 1999      Nick Brok <nick@nbrok.iaehv.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>

#undef DEBUG

int TIMEOUT=30;

#ifndef O_BINARY
#define O_BINARY 0
#endif

char referrer[128];
int content_length;

#define SERVER_PORT 80

int PrintHeader(FILE *f, int content_type)

{
  alarm(TIMEOUT);
  fprintf(f,"HTTP/1.0 200 OK\n");
  switch (content_type)
  { 
   case 't':
    fprintf(f,"Content-type: text/plain\n");
    break;
   case 'g':
    fprintf(f,"Content-type: image/gif\n");
    break;
   case 'j':
    fprintf(f,"Content-type: image/jpeg\n");
    break;
   case 'h':
    fprintf(f,"Content-type: text/html\n");
    break;
  }
  fprintf(f,"Server: uClinux-httpd 0.2.2\n");
  fprintf(f,"Expires: 0\n");
  fprintf(f,"\n");
  alarm(0);
  return(0);
}

int
DoJpeg(FILE *f, char *name)
{
  char *buf;
  FILE * infile;
  int count;
 
  if (!(infile = fopen(name, "r"))) {
    alarm(TIMEOUT);
    fprintf(stderr, "Unable to open JPEG file %s, %d\n", name, errno);
    fflush(f);
    alarm(0);
    return -1;
  }
 
  PrintHeader(f,'j');
 
  copy(infile,f); /* prints the page */
 
  alarm(TIMEOUT);
  fclose(infile);
  alarm(0);
 
  return 0;
}

int
DoGif(FILE *f, char *name)
{
  char *buf;
  FILE * infile;
  int count;

  if (!(infile = fopen(name, "r"))) {
    alarm(TIMEOUT);
    fprintf(stderr, "Unable to open GIF file %s, %d\n", name, errno);
    fflush(f);
    alarm(0);
    return -1;
  }
  
  PrintHeader(f,'g');

  copy(infile,f); /* prints the page */  

  alarm(TIMEOUT);
  fclose(infile);
  alarm(0);
  
  return 0;
}

int
DoDir(FILE *f, char *name)
{
  char *buf;
  DIR * dir;
  struct dirent * dirent;

  if ((dir = opendir(name))== 0) {
    fprintf(stderr, "Unable to open directory %s, %d\n", name, errno);
    fflush(f);
    return -1;
  }
  
  PrintHeader(f,'h');
  
  alarm(TIMEOUT);
  fprintf(f, "<H1>Index of %s</H1>\n\n",name);
  alarm(0);

  if (name[strlen(name)-1] != '/') {
	strcat(name, "/");
  }
  
  while(dirent = readdir(dir)) {
	alarm(TIMEOUT);
  
	fprintf(f, "<p><a href=\"/%s%s\">%s</a></p>\n", name, dirent->d_name, dirent->d_name);
	alarm(0);
  }
  
  closedir(dir);
  return 0;
}

int
DoHTML(FILE *f, char *name)
{
  char *buf;
  FILE *infile;
  int count;
  char * dir = 0;

  if (!(infile = fopen(name,"r"))) {
    alarm(TIMEOUT);
    fprintf(stderr, "Unable to open HTML file %s, %d\n", name, errno);
    fflush(f);
    alarm(0);
    return -1;
  }

  PrintHeader(f,'h');
  copy(infile,f); /* prints the page */  

  alarm(TIMEOUT);
  fclose(infile);
  alarm(0);

  return 0;
}

int
DoText(FILE *f, char *name)
{
  char *buf;
  FILE *infile;
  int count;

  if (!(infile = fopen(name,"r"))) {
    alarm(TIMEOUT);
    fprintf(stderr, "Unable to open text file %s, %d\n", name, errno);
    fflush(f);
    alarm(0);
    return -1;
  }

  PrintHeader(f,'t');
  copy(infile,f); /* prints the page */  

  alarm(TIMEOUT);
  fclose(infile);
  alarm(0);

  return 0;
}

int
ParseReq(FILE *f, char *r)
{
  char *bp;
  struct stat stbuf;
  char * arg;
  char * c;
  int e;
  int raw;

#ifdef DEBUG
  printf("req is '%s'\n", r);
#endif
  
  while(*(++r) != ' ');  /*skip non-white space*/
  while(isspace(*r))
  	r++;
  
  while (*r == '/')
  	r++;

  bp = r;
  /**r = '.';*/
  
  while(*r && (*(r) != ' ') && (*(r) != '?'))
  	r++;
  	
#ifdef DEBUG
  printf("bp='%s', r='%s'\n", bp, r);
#endif
  	
  if (*r == '?')
  {
  	char * e;
  	*r = 0;
  	arg = r+1;
  	if (e = strchr(arg,' ')) 
	{
  		*e = '\0';
  	}
  } else 
    {
  	arg = 0;
  	*r = 0;
    }
  
  c = bp;

  if (c[0] == '\0') strcat(c,".");

  if (c && !stat(c, &stbuf)) 
  {
    if (S_ISDIR(stbuf.st_mode)) 
    { 
    	char * end = c + strlen(c);
    	strcat(c, "/index.html");
    	if (!stat(c, &stbuf)) 
        {
    		DoHTML(f, c);
    	} 
        else 
        {
  		*end = '\0';
		DoDir(f,c);
	}
    }
    else if (!strcmp(r - 4, ".gif"))
      DoGif(f,c);
        else if (!strcmp(r - 4, ".jpg") || !strcmp(r - 5, ".jpeg"))
          DoJpeg(f,c);
            else if (!strcmp(r - 4, ".htm") || !strcmp(r - 5, ".html"))
              DoHTML(f,c);
                else
                  DoText(f,c);
  } else
    {
  	PrintHeader(f,'h');
  	alarm(TIMEOUT);
  	fprintf(f, "<html><head><title>404 File Not Found</title></head>\n");
	fprintf(f, "<body>The requested URL was not found on this server</body></html>\n");
  	alarm(0);
    }
  return 0;
}

void sigalrm(int signo)
{
	/* got an alarm, exit & recycle */
	exit(0);
}

int
HandleConnect(int fd)
{
  FILE *f;

  char buf[160];
  char buf1[160];

  f = fdopen(fd,"a+");
  if (!f) {
    fprintf(stderr, "httpd: Unable to open httpd input fd, error %d\n", errno);
    alarm(TIMEOUT);
    close(fd);
    alarm(0);
    return 0;
  }
  setbuf(f, 0);

  alarm(TIMEOUT);

  if (!fgets(buf, 150, f)) {
    fprintf(stderr, "httpd: Error reading connection, error %d\n", errno);
    fclose(f);
    alarm(0);
    return 0;
  }
#ifdef DEBUG
  printf("buf = '%s'\n", buf);
#endif
    
  alarm(0);

  referrer[0] = '\0';
  content_length = -1;
    
  alarm(TIMEOUT);
  while (fgets(buf1, 150, f) && (strlen(buf1) > 2)) {
    alarm(TIMEOUT);
#ifdef DEBUG
    printf("Got buf1 '%s'\n", buf1);
#endif
    if (!strncasecmp(buf1, "Referer:", 8)) {
      char * c = buf1+8;
      while (isspace(*c))
	c++;
      strcpy(referrer, c);
    } else if (!strncasecmp(buf1, "Referrer:", 9)) {
      char * c = buf1+9;
      while (isspace(*c))
	c++;
      strcpy(referrer, c);
    } else if (!strncasecmp(buf1, "Content-length:", 15)) {
      content_length = atoi(buf1+15);
    } 
  }
  alarm(0);
  
  
  if (ferror(f)) {
    fprintf(stderr, "http: Error continuing reading connection, error %d\n", errno);
    fclose(f);
    return 0;
  }
    
  ParseReq(f, buf);

  alarm(TIMEOUT);
  fflush(f);
  fclose(f);
  alarm(0);

  return 1;
}

int
main(int argc, char *argv[])
{
  int fd, s;
  int len;
  volatile int true = 1;
  struct sockaddr_in ec;
  struct sockaddr_in server_sockaddr;

  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGALRM, sigalrm);

  chroot(HTTPD_DOCUMENT_ROOT);
  chdir("/");

  if (argc > 1 && !strcmp(argv[1], "-i")) {
    /* I'm running from inetd, handle the request on stdin */
    fclose(stderr);
    HandleConnect(0);
    exit(0);
  }

  if((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
    perror("Unable to obtain network");
    exit(1);
  }
  
  if((setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&true, 
		 sizeof(true))) == -1) {
    perror("setsockopt failed");
    exit(1);
  }

  server_sockaddr.sin_family = AF_INET;
  server_sockaddr.sin_port = htons(SERVER_PORT);
  server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  
  if(bind(s, (struct sockaddr *)&server_sockaddr, 
	  sizeof(server_sockaddr)) == -1)  {
    perror("Unable to bind socket");
    exit(1);
  }

  if(listen(s, 8*3) == -1) { /* Arbitrary, 8 files/page, 3 clients */
    perror("Unable to listen");
    exit(4);
  }

  while (1) {
    len = sizeof(ec);
    
    if((fd = accept(s, (void *)&ec, &len)) == -1) {
      exit(5);
      close(s);
    }
    HandleConnect(fd);
  }
}
