#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "extern.h"

#ifndef LINE_MAX
# define LINE_MAX 2048
#endif

int
display_file (const char *name, int code)
{
  char *cp, line[LINE_MAX];
  FILE *fp = fopen (name, "r");
  if (fp != NULL)
    {
      while (fgets (line, sizeof(line), fp) != NULL)
	{
	  cp = strchr (line, '\n');
	  if (cp != NULL)
	    *cp = '\0';
	  lreply (code, "%s", line);
	}
      (void) fflush (stdout);
      (void) fclose (fp);
      return 0;
    }
  return errno;
}

/* Check if a user is in the file PATH_FTPUSERS
   return 1 if yes 0 otherwise.  */
int
checkuser (const char *filename, const char *name)
{
  FILE *fp;
  int found = 0;
  char *p, line[BUFSIZ];

  fp = fopen (filename, "r");
  if (fp != NULL)
    {
      while (fgets (line, sizeof(line), fp) != NULL)
	{
	  if (line[0] == '#')
	    continue;
	  p = strchr (line, '\n');
	  if (p != NULL)
	    {
	      *p = '\0';
	      if (strcmp (line, name) == 0)
		{
		  found = 1;
		  break;
		}
	    }
	}
      (void) fclose (fp);
    }
  return (found);
}
