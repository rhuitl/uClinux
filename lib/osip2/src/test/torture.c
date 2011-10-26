/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc2543-)
  Copyright (C) 2001  Aymeric MOIZARD jack@atosc.org
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#ifdef ENABLE_MPATROL
#include <mpatrol.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <osipparser2/osip_parser.h>
#include <osip2/internal.h>

int test_message (char *msg, int verbose, int clone);
static void usage (void);

static void
usage ()
{
  fprintf (stderr, "Usage: ./torture_test torture_file number [-v] [-c]\n");
  exit (1);
}

int
main (int argc, char **argv)
{
  int success = 1;

  int i;
  int verbose = 0;		/* 1: verbose, 0 (or nothing: not verbose) */
  int clone = 0;		/* 1: verbose, 0 (or nothing: not verbose) */
  char *marker;
  FILE *torture_file;
  char *tmp;
  char *msg;
  char *tmpmsg;
  static int num_test = 0;

  if (argc > 3)
    {
      if (0 == strncmp (argv[3], "-v", 2))
	verbose = 1;
      else if (0 == strncmp (argv[3], "-c", 2))
	clone = 1;
      else
	usage ();
    }

  if (argc > 4)
    {
      if (0 == strncmp (argv[4], "-v", 2))
	verbose = 1;
      else if (0 == strncmp (argv[4], "-c", 2))
	clone = 1;
      else
	usage ();
    }

  if (argc < 3)
    {
      usage ();
    }

  torture_file = fopen (argv[1], "r");
  if (torture_file == NULL)
    {
      usage ();
    }

  /* initialize parser */
  parser_init ();

  i = 0;
  tmp = (char *) osip_malloc (500);
  marker = fgets (tmp, 500, torture_file);	/* lines are under 500 */
  while (marker != NULL && i < atoi (argv[2]))
    {
      if (0 == strncmp (tmp, "|", 1))
	i++;
      marker = fgets (tmp, 500, torture_file);
    }
  num_test++;

  msg = (char *) osip_malloc (100000);	/* msg are under 10000 */
  if (msg == NULL)
    {
      fprintf (stderr, "Error! osip_malloc failed\n");
      return -1;
    }
  tmpmsg = msg;

  if (marker == NULL)
    {
      fprintf (stderr,
	       "Error! The message's number you specified does not exist\n");
      exit (1);			/* end of file detected! */
    }
  /* this part reads an entire message, separator is "|" */
  /* (it is unlinkely that it will appear in messages!) */
  while (marker != NULL && strncmp (tmp, "|", 1))
    {
      osip_strncpy (tmpmsg, tmp, strlen (tmp));
      tmpmsg = tmpmsg + strlen (tmp);
      marker = fgets (tmp, 500, torture_file);
    }

  success = test_message (msg, verbose, clone);
  if (verbose)
    {
      fprintf (stdout, "test %s : ============================ \n", argv[2]);
      fprintf (stdout, "%s", msg);

      if (0 == success)
	fprintf (stdout, "test %s : ============================ OK\n",
		 argv[2]);
      else
	fprintf (stdout, "test %s : ============================ FAILED\n",
		 argv[2]);
    }

  osip_free (msg);
  osip_free (tmp);
  fclose (torture_file);

  return success;
}

int
test_message (char *msg, int verbose, int clone)
{
  osip_message_t *sip;

  {
    char *result;

    /* int j=10000; */
    int j = 1;

    if (verbose)
      fprintf (stdout,
	       "Trying %i sequentials calls to osip_message_init(), osip_message_parse() and osip_message_free()\n",
	       j);
    while (j != 0)
      {
	j--;
	osip_message_init (&sip);
	if (osip_message_parse (sip, msg, strlen(msg)) != 0)
	  {
	    fprintf (stdout, "ERROR: failed while parsing!\n");
	    osip_message_free (sip);
	    return -1;
	  }
	osip_message_free (sip);
      }

    osip_message_init (&sip);
    if (osip_message_parse (sip, msg, strlen(msg)) != 0)
      {
	fprintf (stdout, "ERROR: failed while parsing!\n");
	osip_message_free (sip);
	return -1;
      }
    else
      {
	int i;
	size_t length;
	osip_message_force_update(sip);
	i = osip_message_to_str (sip, &result, &length);
	if (i == -1)
	  {
	    fprintf (stdout, "ERROR: failed while printing message!\n");
	    osip_message_free (sip);
	    return -1;
	  }
	else
	  {
	    if (verbose)
	      fprintf (stdout, "%s", result);
	    if (clone)
	      {
		/* create a clone of message */
		/* int j = 10000; */
		int j = 1;

		if (verbose)
		  fprintf (stdout,
			   "Trying %i sequentials calls to osip_message_clone() and osip_message_free()\n",
			 j);
		while (j != 0)
		  {
		    osip_message_t *copy;

		    j--;
		    i = osip_message_clone (sip, &copy);
		    if (i != 0)
		      {
			fprintf (stdout,
				 "ERROR: failed while creating copy of message!\n");
		      }
		    else
		      {
			char *tmp;
			size_t length;
			osip_message_force_update (copy);
			i = osip_message_to_str (copy, &tmp, &length);
			if (i != 0)
			  {
			    fprintf (stdout,
				     "ERROR: failed while printing message!\n");
			  }
			else
			  {
			    if (0 == strcmp (result, tmp))
			      {
				if (verbose)
				  printf
				    ("The osip_message_clone method works perfectly\n");
			      }
			    else
			      printf
				("ERROR: The osip_message_clone method DOES NOT works\n");
			    if (verbose)
			      printf ("Here is the copy: \n%s\n", tmp);

			    osip_free (tmp);
			  }
			osip_message_free (copy);
		      }
		  }
		if (verbose)
		  fprintf (stdout, "sequentials calls: done\n");
	      }
	    osip_free (result);
	  }
	osip_message_free (sip);
      }
  }
  return 0;
}
