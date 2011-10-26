/* ptylogin.c -- links the current tty to a /bin/login process through
 *               a pty pair
 * Marc SCHAEFER <schaefer@alphanet.ch>
 * Creation: 10/01/98
 * Update:   10/01/98
 * V1.0 PV001
 * DESCRIPTION
 *    This emulates a rlogin -8E -l USER localhost from mgetty's login.conf
 *    without the need for two sockets, two processes, and networking
 *    running.
 *    This allows to prevent direct control of the modem tty by a
 *    malicious user, work-arounding many Denial of Service or even
 *    security problems. Please look at the ``Paranoid Secure Port
 *    Implementation'', RCS revision SPEC,v 1.6 1999/01/05 08:41:46 or
 *    later for all details.
 * USAGE
 *    See manpage.
 * RESULT
 *    0 everything fine
 *    1 couldn't exec() /bin/login or allocate pty.
 *    2 missing argument, illegal login name or not running as root.
 * NOTES
 *    - This should NOT be suid as it is not necessary and it has not
 *      been designed to be run outside of mgetty's login.config.
 * BUGS
 * TODO
 *   - Test
 *   - Do we need to ensure running as root for pty security ?
 *   - Do we need to change tty permission and owner or is it done by
 *     mgetty ?
 *   - Alternative pty allocation code not needing root ? (there is
 *     code floating around for Linux).
 *   - Ask people to review the code and the specification.
 * ASSUMPTIONS
 *    - This is called with root priviledges since this is more secure
 *      in term of tty ownership and pty allocation.
 * COPYING-POLICY
 *    (C) Marc SCHAEFER, under the GPL
 *    parts Copyright (c) 1983, 1988, 1989
 *             The Regents of the University of California
 * BASED-ON
 *    - A problem described by Marc SCHAEFER in the above Paranoid
 *      specification.
 *    - An idea to simplify rlogin and still fix the problems from
 *         "Theodore Y. Ts'o" <tytso@MIT.EDU>
 *    - rlogind and rlogin code from Linux NetKit-0.09, BSD license.
 *    - virtual_connection from Marc SCHAEFER <schaefer@alphanet.ch>, GPL.
 * MODIFICATION-HISTORY
 *    10/01/99  schaefer  Created this file.
 * $Id: ptylogin.c,v 1.1 1999/01/16 17:17:08 gert Exp $
 */

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/ioctl.h>

/* Macro and definitions */

#define MAXIMUM_LOGIN_NAME_LENGTH 8
#define PTS_NAME_SIZE 20
#define _PATH_LOGIN "/bin/login"
#define BUFFER_LENGTH 4096

#undef  MGETTY_HAS_SET_OWNER_AND_MODE  /* ptylogin does it */

/* Public function definitions and hacks */

/* BUGS
 *    - Should be in libbsd.h or similar include file.
 */
pid_t forkpty(int *, char *, struct termios *, struct winsize *);

/* Private type definitions */

#ifndef fd_t
typedef int fd_t;
#endif /* !fd_t */

/* Private function definitions */

/* NAME
 *    connect_login
 * DESCRIPTION
 *    Connects this process to the /bin/login process through a pty
 *    pair. Do any local tty initialization (including chmod()/chown()).
 * RESULT
 *    exit code
 *       0 session terminated normally (hangup or exit)
 *       1 couldn't spawn child or open ptys.
 * NOTES
 * BUGS
 * TODO
 */
static int connect_login(char *login_name);

/* NAME
 *    reject_login_name
 * DESCRIPTION
 *    Verify the constraints on the login name, which are that it doesn't
 *    dashes (-) or spaces (only normal spaces), and it 8 characters
 *    long or less.
 * RESULT
 *    0 if the constraint DO apply and the login name should be
 *    accepted, else different of zero and the login should be rejected.
 * NOTES
 *    - We tested this function with 7, 8 and 9 characters. We also tested
 *      one hash at the end and beginning and one space at the end. In all
 *      case the function answered as expected.
 * BUGS
 * TODO
 *    - Theoretically those constraints are already mostly handled by
 *      mgetty. Check this. Until then we do it here.
 */
static int reject_login_name(char *login_name);

/* NAME
 *    set_raw
 * DESCRIPTION
 *    Sets the stdin tty to raw (if mode == 1), else cooked.
 * RESULT
 *    NONE
 * NOTES
 *    - Each call to set_raw(0) must have been after a corresponding
 *      and unnested call to set_raw(1) because of internal state.
 * BUGS
 * TODO
 */
static void set_raw(int mode);

/* Public constants */

char rcsid[] =
  "$Id: ptylogin.c,v 1.1 1999/01/16 17:17:08 gert Exp $";


/* Private constants */

/* Private variables */

static struct winsize win = { 0, 0, 0, 0 };
static struct termio saved; /* Internal state for set_raw() */

/* Function implementation */

int main(int argc, char **argv) {
   if (argc == 2) {
      if ((getuid() == 0) && (geteuid() == 0)) {
	 if (!reject_login_name(argv[1])) {
	    exit(connect_login(argv[1]));
	 }
	 else {
	    fprintf(stderr,
                    "%s: illegal length or character(s) in login name.\n", 
                    argv[0]);
	    exit(2);
	 }
         /* NOT REACHED */
      }
      else {
	 fprintf(stderr,
                 "%s: not running as root.\n",
                 argv[0]);
	 exit(2);         
      }
      /* NOT REACHED */
   }
   else {
      fprintf(stderr, "%s login-name\n%s: bad args.\n", argv[0], argv[0]);
      exit(2);
   }

   /* NOT REACHED */
}

static int reject_login_name(char *login_name) {
   return (strlen(login_name) > MAXIMUM_LOGIN_NAME_LENGTH)
          || (strchr(login_name, ' '))
          || (strchr(login_name, '-'));
}

static int connect_login(char *login_name) {
   pid_t pid;
   fd_t master_fd;
   char line[PTS_NAME_SIZE];

#ifndef MGETTY_HAS_SET_OWNER_AND_MODE
   if (fchown(0, 0, 0)) {
      perror("fchown()");
      return 1;
   }
   else if (fchmod(0, 0600)) {
      perror("fchmod()");
      return 1;
   }
#endif /* !MGETTY_HAS_SET_OWNER_AND_MODE */

   switch (pid = forkpty(&master_fd, line, NULL, &win)) {
      case 0:
         /* Child. Setup slave and exec /bin/login */

         /* ASSUMPTIONS
          *    - No other open file except slave pty, which is on 0/1/2.
          *    - Controlling tty set.
          */

         /* NOTES
          *    - Keeping whole environment.
          */
         execl(_PATH_LOGIN, "login", login_name, NULL);

         return 1; /* if arriving here, something wrong */
         break;
      default:
         /* Parent */
         if (pid < 0) {
            if (errno == ENOENT) {
               perror("Out of ptys");
            }
            else {
               perror("forkpty()");
            }
            return 1;
         }
         else {
            int ok = 1;
	    int nfound;
	    fd_set readfds;
	    fd_set writefds;
	    char from[BUFFER_LENGTH];
	    char to[BUFFER_LENGTH];
	    int infrom = 0;
	    int into = 0;
	    int temp;

            /* Transfer bytes transparently until SIGHUP or EOF */

            set_raw(1);

            while (ok) {
	       FD_ZERO(&readfds);
	       FD_ZERO(&writefds);

	       FD_SET(0, &readfds);
	       FD_SET(master_fd, &readfds);

	       if (infrom) {
		  FD_SET(1, &writefds);
	       }
	       if (into) {
		  FD_SET(master_fd, &writefds);
	       }

	       /* from: buffer used to store data from remote site to be output
		*       to stdout (1). (read from master_fds)
		* to:   buffer used to store data from `modem' to be output to
		*       socket. (read from 0).
		*/
	       nfound = select(master_fd + 1, &readfds, &writefds, NULL, NULL);
	       if (nfound) {
		  if (FD_ISSET(0, &readfds)) {
		     if (into < BUFFER_LENGTH) {
			temp = read(0, to + into, BUFFER_LENGTH - into);
			if (temp == -1 || temp == 0 ) {
			   ok = 0;
			}
			else {
			   into += temp;
			}
		     }
		     /* else we will do it later. */
		  }
		  if (FD_ISSET(master_fd, &readfds)) {
		     if (infrom < BUFFER_LENGTH) {
			temp = read(master_fd, from + infrom, BUFFER_LENGTH - infrom);
			if (temp == -1 || temp == 0) {
			   ok = 0;
			}
			else {
			   infrom += temp;
			}
		     }
		     /* else we will do it later. */
		  }
		  if (FD_ISSET(1, &writefds)) {
		     if (infrom > 0) {
			temp = write(1, from, infrom);
			if (temp == -1 ) {
			   ok = 0;
			}
			else {
			   infrom -= temp;
			}
		     }
		  }
		  if (FD_ISSET(master_fd, &writefds)) {
		     if (into > 0) {
			temp = write(master_fd, to, into);
			if (temp == -1 ) {
			   ok = 0;
			}
			else {
			   into -= temp;
			}
		     }
		  }
	       }
	    }

            set_raw(0);


            return 0;
         }
         break;
   }
   
   printf("connect");
   return 0;
}

void set_raw(int mode) {
   struct termio tty;

   /* ASSUMPTION
    *    - Doing it for 0 also does it for 1 (device-wide).
    */

   if (!mode) {
      ioctl(0, TCSETAW, &saved);
   }
   else {
      ioctl(0, TCGETA, &tty);
      ioctl(0, TCGETA, &saved);

      tty.c_iflag = (IGNBRK);

      /* No echo, crlf mapping, INTR, QUIT, delays, no erase/kill */
      tty.c_lflag &= ~(ECHO | ICANON | ISIG);

      tty.c_oflag = 0;        /* Transparent output */

      tty.c_cflag &= ~PARENB; /* Same baud rate, disable parity */
      tty.c_cflag |= CS8;     /* Set character size = 8 */

      /* NOTES
       *    - We assume mgetty set crtscts.
       */

      tty.c_cc[VMIN] = 1; /* This many chars satisfies reads */
      tty.c_cc[VTIME] = 1;    /* or in this many tenths of seconds */

      ioctl(0, TCSETAW, &tty);
   }
}
