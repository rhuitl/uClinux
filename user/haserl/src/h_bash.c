/*-----------------------------------------------------------------
 * haserl functions specific to a bash/ash/dash shell
 * Copyright (c) 2003-2007    Nathan Angelacos (nangel@users.sourceforge.net)
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, version 2, as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 ------------------------------------------------------------------------- */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

#include "common.h"
#include "h_error.h"
#include "h_bash.h"
#include "h_script.h"
#include "haserl.h"

/* Local subshell variables */
static int subshell_pipe[2];
static int subshell_pid;


void
bash_setup (char *shell, list_t * env)
{
  int retcode = 0;
  int count;
  argv_t *argv;
  char *av[20];
  list_t *next;

  if (shell == NULL)
    return;

  retcode = pipe (&subshell_pipe[PARENT_IN]);
  if (retcode == 0)
    {
#ifdef __uClinux__
      subshell_pid = vfork ();
#else
      subshell_pid = fork ();
#endif
      if (subshell_pid == -1)
	{
	  die_with_message (NULL, NULL, g_err_msg[E_SUBSHELL_FAIL]);
	}

      if (subshell_pid == 0)
	{
	  /* I'm the child, connect stdin to the parent */
	  dup2 (subshell_pipe[PARENT_IN], STDIN_FILENO);
	  close (subshell_pipe[PARENT_IN]);
	  close (subshell_pipe[PARENT_OUT]);
	  count = argc_argv (shell, &argv, "");
	  if (count > 19)
	    {
	      /* over 20 command line args, silently truncate */
	      av[19] = "\0";
	      count = 18;
	    }
	  while (count >= 0)
	    {
	      av[count] = argv[count].string;
	      count--;
	    }
	  

	  /* populate the environment */
  	while (env)
    	{
      	next = env->next;
     	 putenv (env->buf);
      	env = next;
   	 }
	  
	  execv (argv[0].string, av);
	  free (argv);

	  /* if we get here, we had a failure */
	  die_with_message (NULL, NULL, g_err_msg[E_SUBSHELL_FAIL]);
	}
      else
	{
	  /* I'm parent, move along please */
	  close (subshell_pipe[PARENT_IN]);
	}
    }

  /* control should get to this point only in the parent.
   */
}

void
bash_destroy (void)
{
  int status;
  waitpid (subshell_pid, &status, 0);
}


void
bash_exec (buffer_t * buf, char *str)
{
  buffer_add (buf, str, strlen (str));
  return;
}

/* Run the echo command in a subshell */
void
bash_echo (buffer_t * buf, char *str, size_t len)
{
/* limits.h would tell us the ARG_MAX characters we COULD send to the echo command, but
 * we will take the (ancient) POSIX1 standard of 4K, subtract 1K from it and use that
 * as the maxmimum.    The Linux limit appears to be 128K, so 3K will fit. */

  static char echo_start[] = "echo -n '";
  static char echo_quote[] = "'\\''";
  static char echo_end[] = "'\n";
  const size_t maxlen = 3096;
  size_t pos;

  if (len == 0)
    return;
  pos = 0;

  buffer_add (buf, echo_start, strlen (echo_start));
  while (pos < len)
    {
      if (str[pos] == '\'')
	buffer_add (buf, echo_quote, strlen (echo_quote));
      else
	buffer_add (buf, str + pos, 1);
      pos++;
      if ((pos % maxlen) == 0)
	{
	  buffer_add (buf, echo_end, strlen (echo_end));
	  buffer_add (buf, echo_start, strlen (echo_start));
	}
    }
  buffer_add (buf, echo_end, strlen (echo_end));
}


/* do an evaluation in a subshell */
void
bash_eval (buffer_t * buf, char *str, size_t len)
{
  static char echo_start[] = "echo -n ";
  static char echo_end[] = "\n";
  if (len == 0)
    return;

  buffer_add (buf, echo_start, strlen (echo_start));
  buffer_add (buf, str, len);
  buffer_add (buf, echo_end, strlen (echo_end));
}


void
bash_doscript (buffer_t * script, char *name)
{
  static char postfix[] = "\nexit\n";

  /* dump the script to the subshell */
  write (subshell_pipe[PARENT_OUT], script->data, script->ptr - script->data);

  /* write the postfix */
  write (subshell_pipe[PARENT_OUT], postfix, strlen (postfix));


  return;

}
