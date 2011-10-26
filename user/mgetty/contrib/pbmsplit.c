From durham.ac.uk!A.J.Scholl Wed Jan  4 14:05:37 1995
Return-Path: <A.J.Scholl@durham.ac.uk>
Received: by greenie.muc.de (/\==/\ Smail3.1.24.1 #24.2)
	id <m0rPVPA-00015dC@greenie.muc.de>; Wed, 4 Jan 95 14:05 MET
Received: from ben.britain.eu.net ([192.91.199.254]) by colin.muc.de with SMTP id <25577-1>; Wed, 4 Jan 1995 14:05:27 +0100
Received: from durham.ac.uk by ben.britain.eu.net via JANET with NIFTP (PP) 
          id <sg.08575-0@ben.britain.eu.net>; Wed, 4 Jan 1995 13:04:32 +0000
Received: from gauss.dur.ac.uk by durham.ac.uk; Wed, 4 Jan 95 13:03:52 GMT
From: Tony Scholl <A.J.Scholl@durham.ac.uk>
Date: Wed, 4 Jan 1995 14:03:50 +0100
Message-Id: <AA03302.9501041303.gauss@uk.ac.durham>
Received: from germain.durham.ac.uk (germain.dur) by uk.ac.durham.gauss;
          Wed, 4 Jan 95 13:03:50 GMT
Received: by germain.durham.ac.uk (4.1/SMI-4.1) id AA14688;
          Wed, 4 Jan 95 13:03:35 GMT
To: gert@greenie.muc.de
Subject: pbmsplit
Status: RO

Hi,

A promised, here's a late Christmas present (and a pretty crummy one, too ---
_my_ Christmas present was a ZyXEL...) but I've found it useful at times.

Tony

---------------------------------cut here------------------------------------
/* pbmsplit.c: split a pbm file into pieces of specified size, with 
   overlapping/breaking on blank rows.

   Usage: pbmsplit [-w rows|-o rows] [-n rows] {-|infile} [outfile]

   Optional argument -n is number of rows for each output file (default 2400).

   Optional argument -w is number of rows by which it is permissible to shorten
   an output file to search for a whitespace-only row to break (default 0).

   Optional argument -o is number of rows to overlap (default 0). You cannot 
   specify both -o and -w.

   Argument - means read from stdin (in which case outfile MUST be given)
   Output is written to outfile.001, etc; outfile defaults to infile.

   This was put together by Tony Scholl (a.j.scholl@durham.ac.uk). I've  
   tested it a little, and it seems to work. But the code is far from
   brilliant, so if you can write a better/working one please do.....
*/

#define MAXROWS 2400
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int row_len;

void usage ()
{
  fprintf (stderr, "Usage: pbmsplit [-w rows|-o rows] [-n rows] {-|infile} [outfile]\n");
  exit (-1);
}

void fatal (char *s)
{
  fprintf (stderr, s);
  fprintf (stderr, "\n");
  exit (-1);
}

void copy_rows (FILE *inf, FILE *outf, int r)
{
  int c, n;
  n = r * row_len;
  while ((n-- > 0) && ((c = getc(inf)) != EOF))
    putc(c, outf);
  if (n > 0)
    {
      fclose (inf);
      fclose (outf);
      fatal ("Unexpected EOF");
    }
}

void copy_saved_rows (FILE *outf, char *buf, int r)
{
  int n;
  n = r * row_len;
  while (n-- > 0)
    putc (*(buf++), outf);
}

void copy_and_save_rows (FILE *inf, FILE *outf, char *buf, int r)
{
  int c, n;
  n = r * row_len;
  while ((n-- > 0) && ((c = getc (inf)) != EOF))
    {
      putc (c, outf);
      *(buf++) = c;
    }
  if (n > 0)
    {
      fclose (inf);
      fclose (outf);
      fatal ("Unexpected EOF");
    }
}


/* function to copy characters and return the OR of them */
int copy_row2 (FILE *inf, FILE *outf)
{
  int c, n;
  int d = 0;
  n = row_len;
  while ((n-- > 0) && ((c = getc (inf)) != EOF))
    {
      putc (c, outf);
      d |= c;
    }
  if (n > 0)
    {
      fclose (inf);
      fclose (outf);
      fatal ("Unexpected EOF");
    }
  return (d);
}

int put_white (FILE *outf, int r)
{
  int n;
  n = r * row_len;
  while (n-- > 0)
    putc ('\0', outf);
}

main (int argc, char *argv[])
{
  int count = 0;
  int over_rows = 0;
  int max_rows = MAXROWS;
  int min_rows = 0;
  int frows, fcols;
  int rows_remaining;
  char header[64];
  FILE *in_f;
  FILE *out_f;
  char *in_fname;
  char *out_fbasename;
  char out_fname[256];
  char *over_buf;

/* parse arguments */
  if (argc == 1)
    usage ();
  while ((**++argv == '-') && (*++*argv != '\0') && (argc-- > 3))
    {
      switch (**(argv++))
	{
	case 'o':
	  over_rows = atoi (*argv); break;
	case 'w': 
	  min_rows = - atoi (*argv); break;
	case 'n': 
	  max_rows = atoi (*argv); break;
	default: 
	  fprintf (stderr, "Invalid option \"-%s\"\n", *(--argv)); 
	  usage ();
	}
      argc--;
    }
  min_rows += max_rows;
  in_fname = *argv;
  switch (argc)
    {
    case 3: argv++;
    case 2: out_fbasename = *argv; break; 
    default: usage ();
    }
  if ( out_fbasename[0] == '\0' )
    usage ();

  if ((over_rows > 0) && (min_rows != max_rows))
      fprintf (stderr, "Warning: you cannot use both -o and -w! I'm ignoring -w.\n");
  if (over_rows > max_rows/2)
    fatal ("You have specified an excessive overlap!");

  if (*in_fname != '\0')
    in_f = fopen (in_fname, "r");
  else
    in_f = stdin;
  if (in_f == NULL)
    {
      fprintf (stderr, "Cannot open %s for reading\n", in_fname);
      exit (-1);
    }
  fgets (header, 62, in_f);
    if (strcmp (header, "P4\n") != 0)
      fatal ("Wrong magic number");
  fgets (header, 63, in_f);
  fcols = atoi (strtok (header, " "));
  frows = rows_remaining = atoi (strtok (NULL, " "));

  row_len = (fcols + 7) / 8;

  if (over_rows == 0) /* no overlapping */
    {
      while (rows_remaining > 0)
	{
	  sprintf (out_fname, "%s.%03d", out_fbasename, ++count);
	  if ((out_f = fopen (out_fname, "w")) == (FILE *)NULL)
	    {
	      close (in_f);
	      fatal ("Cannot open output file");
	    }
	  if (rows_remaining < max_rows)
	    /* put the lot */
	    {
	      fprintf (out_f, "P4\n%d %d\n", fcols, rows_remaining);
	      copy_rows (in_f, out_f, rows_remaining);
	      rows_remaining = 0;
	    }
	  else
	    /* first put min_rows */
	    {
	      int j = min_rows;
	      fprintf (out_f, "P4\n%d %d\n", fcols, max_rows);
	      copy_rows (in_f, out_f, min_rows);
	      /* now look for white rows */
	      while ((j < max_rows) && (j++) && copy_row2 (in_f, out_f))
		;
	      rows_remaining -= j;
	      put_white (out_f, max_rows-j);
	    }
	  /* now close outfile */
	  fclose (out_f);
	}
    }
  else /* do overlapping */
    {
      if ((over_buf = (char *)malloc (over_rows * row_len + 1)) == NULL)
	  fatal ("Cannot allocate memory");
      while (rows_remaining > 0)
	{
	  sprintf (out_fname, "%s.%03d", out_fbasename, ++count);
	  if ((out_f = fopen (out_fname, "w")) == (FILE *)NULL)
	    {
	      close (in_f);
	      fatal ("Cannot open output file");
	    }
	  if (count == 1)
	    {
	      if (rows_remaining <= max_rows)
		/* put the lot */
		{
		  fprintf (out_f, "P4\n%d %d\n", fcols, rows_remaining);
		  copy_rows (in_f, out_f, rows_remaining);
		  rows_remaining = 0;
		}
	      else
		/* put a page, saving overlap */
		{
		  fprintf (out_f, "P4\n%d %d\n", fcols, max_rows);
		  copy_rows (in_f, out_f, max_rows - over_rows);
		  copy_and_save_rows (in_f, out_f, over_buf, over_rows);
		  rows_remaining -= max_rows;
		}
	    }
	  else /* count > 1 */
	    {
	      if (rows_remaining <= max_rows - over_rows)
		/* put the lot */
		{
		  fprintf (out_f, "P4\n%d %d\n", fcols, rows_remaining + over_rows);
		  copy_saved_rows (out_f, over_buf, over_rows);
		  copy_rows (in_f, out_f, rows_remaining);
		  rows_remaining = 0;
		}
	      else
		{
		  fprintf (out_f, "P4\n%d %d\n", fcols, max_rows);
		  copy_saved_rows (out_f, over_buf, over_rows);
		  copy_rows (in_f, out_f, max_rows - 2 * over_rows);
		  copy_and_save_rows (in_f, out_f, over_buf, over_rows);
		  rows_remaining -= max_rows - over_rows;
		}
	    }
	  /* now close outfile */
	  fclose (out_f);
	}
    }
  fclose (in_f);
}

/******************************* end ****************************************/

