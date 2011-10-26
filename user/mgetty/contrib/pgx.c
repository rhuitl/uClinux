#if 0
From ursa-major.spdcc.com!uucp Tue Oct 18 22:28:02 1994
Return-Path: <uucp@ursa-major.spdcc.com>
Received: by greenie.muc.de (/\==/\ Smail3.1.24.1 #24.2)
	id <m0qxM4e-0002T0C@greenie.muc.de>; Tue, 18 Oct 94 22:28 MET
Received: from ursa-major.spdcc.com ([140.186.80.3]) by colin.muc.de with SMTP id <25577(1)>; Tue, 18 Oct 1994 22:27:47 +0100
Received: by ursa-major.spdcc.com with sendmail-5.65/4.7 
	id <AA26019@ursa-major.spdcc.com>; Tue, 18 Oct 94 17:12:35 -0400
Received: by crucible Tue, 18 Oct 94 17:09:47 EDT; id AA26935
Date: Tue, 18 Oct 1994 22:09:00 +0100
From: Winston Edmond <wbe@psr.com>
Subject: Mgetty contribution, part 11 of 11
To: gert@greenie.muc.de
Message-Id: <9410181712.AA26017@spdcc.com>
Status: RO

part 11: contrib/pgx.c           Count pages / extract page

Compiles with:  gcc -O2 -o pgx pgx.c

Installation: I put it in /usr/local/bin/.

---------------------------------------------------------------------------
#endif
/* Count pages or extract a page from a file */

/* Usage:  pgx [-<lines per page>] [<page number>]
   Without the page number, counts pages and prints result on stdout.
   With the page number, copy that one page from stdin to stdout.

   94Oct15  WBE  initial version
 */

#include <stdio.h>

#define false 0
#define true 1

int main (int argc, char *argv[])
{
  int lines_per_page = 60;
  int curpage, curline;		/* current page and line numbers */
  int c, i;
  int onpage = false;		/* (bool) true when requested page reached */
  int wanted_page = 0;		/* page to extract (0 if just counting) */
  int empty;			/* true if no chars on page yet */

    /* process command line arguments */
    if (argc > 3) {
      usage:
      fprintf (stderr, "Usage: %s [-<lines per page>] [<page number>]\n",
	       argv[0]);
      exit (1);
      }
    i = 1;
    if (argc > 1  &&  argv[1][0] == '-') {
      c = argv[1][1];
      if (! isdigit (c))  goto usage;
      lines_per_page = atoi (argv[i]+1);
      i += 1;
      }
    if (i < argc) {
      c = argv[i][0];
      if (! isdigit (c))  goto usage;
      wanted_page = atoi (argv[i]);
      if (wanted_page <= 0) {	/* non-numeric or bad argument */
	fprintf (stderr, "Page numbers must be > 0.\n");
	goto usage;
	}
      }

    /* continues */

    /* main continued */

    curpage = 0,  empty = true;
    while ( (c = getchar()) != EOF ) {
      if (empty) {		/* there's at least 1 more char in file */
	empty = false;
	not_empty:
	onpage = (++curpage == wanted_page);
	curline = 1;
	}
      if (c == '\f')  {
	if (onpage)  exit (0);
	c = getchar ();
	if (c == '\n')  c = getchar ();  /* ignore LF after FF */
	if (c == EOF)  break;	/* ignore page breaks that end document */
	goto not_empty;
	}
      if (onpage)  putchar (c);
      if (c == '\n'  &&  ++curline > lines_per_page) {
	if (onpage)  exit (0);
	empty = true;
	}
      }
    if (onpage)   exit (0);

    if (wanted_page > 0) {
      fprintf (stderr, "No page %d in input\n", wanted_page);
      exit (2);
      }

    printf ("%d", curpage);	/* page count */
    exit (0);			/* normal exit */
}

