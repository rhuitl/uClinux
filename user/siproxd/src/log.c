/*
    Copyright (C) 2002-2005  Thomas Ries <tries@gmx.net>

    This file is part of Siproxd.
    
    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    
    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/


#include "config.h"
#include "log.h"

#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <signal.h>

static char const ident[]="$Id: log.c,v 1.18 2005/01/08 10:41:46 hb9xar Exp $";

/* module local variables */
static int log_to_stderr=0;
static int debug_pattern=0;

static int debug_listen_port=0;
static int debug_listen_fd=0;
static int debug_fd=0;
static char outbuf[512];
/*
 * What shall I log to syslog?
 *   0 - DEBUGs, INFOs, WARNINGs and ERRORs
 *   1 - INFOs, WARNINGs and ERRORs (this is the default)
 *   2 - WARNINGs and ERRORs
 *   3 - only ERRORs
 *   4 - absolutely nothing
 */
static int silence_level=1;

/*
 * Mutex for threat synchronization when writing log data
 *
 * use a 'fast' mutex for synchronizing - as these are portable... 
 */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_set_pattern(int pattern) {
   debug_pattern=pattern;
   return;
}

int  log_get_pattern(void) {
   return debug_pattern;
}

void log_set_stderr(int tostdout) {
   log_to_stderr=tostdout;
   return;
}

void log_set_silence(int level) {
   silence_level=level;
   return;
}

/*
 * TCP logging
 */
void log_set_listen_port(int port){
   debug_listen_port = port;
   log_tcp_listen();
   return;
}

void log_tcp_listen(void) {
   struct sockaddr_in my_addr;
   int sts, on=1;
   int flags;

   /* disabled in configuration? */
   if (debug_listen_port == 0) {
      debug_listen_fd=-1;
      return;
   }

   /* ignore SIGPIPE of lost TCP connection */
   signal (SIGPIPE, SIG_IGN);

   memset(&my_addr, 0, sizeof(my_addr));
   my_addr.sin_family = AF_INET;
   my_addr.sin_port = htons(debug_listen_port);

   debug_listen_fd=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
   INFO("DEBUG listener on TCP port %i",debug_listen_port);
   if (debug_listen_fd < 0) {
      ERROR("socket returned error [%i:%s]",errno, strerror(errno));
      return;
   }

   if (setsockopt(debug_listen_fd, SOL_SOCKET, SO_REUSEADDR, &on , sizeof(on)) < 0) {
      ERROR("socket returned error [%i:%s]",errno, strerror(errno));
      return;
   }


   sts=bind(debug_listen_fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
   if (sts != 0) {
      ERROR("bind returned error [%i:%s]",errno, strerror(errno));
      close(debug_listen_fd);
      debug_listen_fd=-1;
      return;
   }

   /* set non-blocking */
   flags = fcntl(debug_listen_fd, F_GETFL);
   if (flags < 0) {
      ERROR("fcntl returned error [%i:%s]",errno, strerror(errno));
      close(debug_listen_fd);
      debug_listen_fd=-1;
      return;
   }
   if (fcntl(debug_listen_fd, F_SETFL, (long) flags | O_NONBLOCK) < 0) {
      ERROR("fcntl returned error [%i:%s]",errno, strerror(errno));
      close(debug_listen_fd);
      debug_listen_fd=-1;
      return;
   }

   listen (debug_listen_fd, 1);
   return;
}

void log_tcp_connect(void) {
   int sts;
   fd_set fdset;
   struct timeval timeout;
   int tmpfd;

   if (debug_listen_fd <= 0) return;

   timeout.tv_sec=0;
   timeout.tv_usec=0;

   FD_ZERO(&fdset);
   FD_SET (debug_listen_fd, &fdset);

   sts=select(debug_listen_fd+1, &fdset, NULL, NULL, &timeout);
   if (sts > 0) {
      if (debug_fd != 0) {
         tmpfd=accept(debug_listen_fd, NULL, NULL);
         close(tmpfd);
         INFO("Rejected DEBUG TCP connection");
      } else {
         debug_fd=accept(debug_listen_fd, NULL, NULL);
         INFO("Accepted DEBUG TCP connection [fd=%i]", debug_fd);
         INFO(PACKAGE"-"VERSION"-"BUILDSTR" "UNAME);
      }
   }

   /* check the TCP connection */
   if (debug_fd > 0) {
      timeout.tv_sec=0;
      timeout.tv_usec=0;

      FD_ZERO(&fdset);
      FD_SET (debug_fd, &fdset);

      sts=select(debug_fd+1, &fdset, NULL, NULL, &timeout);
      if (sts > 0) {
         char buf[32];
         sts = recv(debug_fd, buf, sizeof(buf), 0);
         /* got disconnected? */
         if (sts == 0) {
            close(debug_fd);
            INFO("Disconnected DEBUG TCP connection [fd=%i]", debug_fd);
            debug_fd=0;
         }
      }
   }
   return;
}


/* for all the LOGGING routines:
   They should figure out if we are running as a daemon, then write
   their stuff to syslog or something like that
*/


void log_debug(int class, char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;
   char string[128];

   if ((debug_pattern & class) == 0) return;

   va_start(ap, format);

   pthread_mutex_lock(&log_mutex);
   /*
    * DEBUG output is either STDOUT or SYSLOG, but not both
    */
   if (log_to_stderr) {
      /* not running as daemon - log to STDERR */
      time(&t);
      tim=localtime(&t);
      fprintf(stderr,"%2.2i:%2.2i:%2.2i %s:%i ", tim->tm_hour,
                      tim->tm_min, tim->tm_sec, file, line);
      vfprintf(stderr, format, ap);
      fprintf(stderr,"\n");
      fflush(stderr);
   } else if (silence_level < 1) {
      /* running as daemon - log via SYSLOG facility */
      vsnprintf(string, sizeof(string), format, ap);
      syslog(LOG_DAEMON|LOG_DEBUG, "%s:%i %s", file, line, string);
   }
   /*
    * Log to TCP
    */
   if (debug_fd > 0) {
      /* log to TCP socket */
      time(&t);
      tim=localtime(&t);
      snprintf(outbuf, sizeof(outbuf) ,"%2.2i:%2.2i:%2.2i %s:%i ",
                       tim->tm_hour, tim->tm_min, tim->tm_sec, file, line);
      write(debug_fd, outbuf, strlen(outbuf));
      vsnprintf(outbuf, sizeof(outbuf) , format, ap);
      write(debug_fd, outbuf, strlen(outbuf));
      snprintf(outbuf, sizeof(outbuf) ,"\n");
      write(debug_fd, outbuf, strlen(outbuf));
   }
   pthread_mutex_unlock(&log_mutex);

   va_end(ap);
   return;

}


void log_error(char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;
   char string[128];

   va_start(ap, format);

   pthread_mutex_lock(&log_mutex);
   /*
    * INFO, WARN, ERROR output is always to syslog and if not daemonized
    * st STDOUT as well.
    */
   if (log_to_stderr) {
      /* not running as daemon - log to STDERR */
      time(&t);
      tim=localtime(&t);
      fprintf(stderr,"%2.2i:%2.2i:%2.2i ERROR:%s:%i ",tim->tm_hour,
                      tim->tm_min, tim->tm_sec, file, line);
      vfprintf(stderr, format, ap);
      fprintf(stderr,"\n");
      fflush(stderr);
   }
   if (silence_level < 4) {
      /* running as daemon - log via SYSLOG facility */
      vsnprintf(string, sizeof(string), format, ap);
      syslog(LOG_USER|LOG_WARNING, "%s:%i ERROR:%s", file, line, string);
   }
   /*
    * Log to TCP
    */
   if (debug_fd > 0) {
      /* log to TCP socket */
      time(&t);
      tim=localtime(&t);
      snprintf(outbuf, sizeof(outbuf) ,"%2.2i:%2.2i:%2.2i ERROR:%s:%i ",
                       tim->tm_hour, tim->tm_min, tim->tm_sec, file, line);
      write(debug_fd, outbuf, strlen(outbuf));
      vsnprintf(outbuf, sizeof(outbuf) , format, ap);
      write(debug_fd, outbuf, strlen(outbuf));
      snprintf(outbuf, sizeof(outbuf) ,"\n");
      write(debug_fd, outbuf, strlen(outbuf));
   }
   pthread_mutex_unlock(&log_mutex);

   va_end(ap);
   return;

}


void log_warn(char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;
   char string[128];

   va_start(ap, format);

   pthread_mutex_lock(&log_mutex);
   /*
    * INFO, WARN, ERROR output is always to syslog and if not daemonized
    * st STDOUT as well.
    */
   if (log_to_stderr) {
      /* not running as daemon - log to STDERR */
      time(&t);
      tim=localtime(&t);
      fprintf(stderr,"%2.2i:%2.2i:%2.2i WARNING:%s:%i ",tim->tm_hour,
                      tim->tm_min, tim->tm_sec,file,line);
      vfprintf(stderr, format, ap);
      fprintf(stderr,"\n");
      fflush(stderr);
   }
   if (silence_level < 3) {
      /* running as daemon - log via SYSLOG facility */
      vsnprintf(string, sizeof(string), format, ap);
      syslog(LOG_DAEMON|LOG_NOTICE, "%s:%i WARNING:%s", file, line, string);
   }
   /*
    * Log to TCP
    */
   if (debug_fd > 0) {
      /* log to TCP socket */
      time(&t);
      tim=localtime(&t);
      snprintf(outbuf, sizeof(outbuf) ,"%2.2i:%2.2i:%2.2i WARNING:%s:%i ",
                       tim->tm_hour, tim->tm_min, tim->tm_sec, file, line);
      write(debug_fd, outbuf, strlen(outbuf));
      vsnprintf(outbuf, sizeof(outbuf) , format, ap);
      write(debug_fd, outbuf, strlen(outbuf));
      snprintf(outbuf, sizeof(outbuf) ,"\n");
      write(debug_fd, outbuf, strlen(outbuf));
   }
   pthread_mutex_unlock(&log_mutex);
   
   va_end(ap);
   return;

}


void log_info(char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;
   char string[128];

   va_start(ap, format);

   pthread_mutex_lock(&log_mutex);
   /*
    * INFO, WARN, ERROR output is always to syslog and if not daemonized
    * st STDOUT as well.
    */
   if (log_to_stderr) {
      /* not running as daemon - log to STDERR */
      time(&t);
      tim=localtime(&t);
      fprintf(stderr,"%2.2i:%2.2i:%2.2i INFO:%s:%i ",tim->tm_hour,
                      tim->tm_min, tim->tm_sec,file,line);
      vfprintf(stderr, format, ap);
      fprintf(stderr,"\n");
      fflush(stderr);
   }
   if (silence_level < 2) {
      /* running as daemon - log via SYSLOG facility */
      vsnprintf(string, sizeof(string), format, ap);
      syslog(LOG_DAEMON|LOG_NOTICE, "%s:%i INFO:%s", file, line, string);
   }
   /*
    * Log to TCP
    */
   if (debug_fd > 0) {
      /* log to TCP socket */
      time(&t);
      tim=localtime(&t);
      snprintf(outbuf, sizeof(outbuf) ,"%2.2i:%2.2i:%2.2i INFO:%s:%i ",
                       tim->tm_hour, tim->tm_min, tim->tm_sec, file, line);
      write(debug_fd, outbuf, strlen(outbuf));
      vsnprintf(outbuf, sizeof(outbuf) , format, ap);
      write(debug_fd, outbuf, strlen(outbuf));
      snprintf(outbuf, sizeof(outbuf) ,"\n");
      write(debug_fd, outbuf, strlen(outbuf));
   }
   pthread_mutex_unlock(&log_mutex);
   
   va_end(ap);
   return;

}


void log_dump_buffer(int class, char *file, int line,
                     char *buffer, int length) {
   int i, j;
   char tmp[8], tmplin1[80], tmplin2[80];

   if ((debug_pattern & class) == 0) return;
   if ((!log_to_stderr) && (debug_fd <= 0)) return;

   pthread_mutex_lock(&log_mutex);
   if (log_to_stderr) fprintf(stderr,  "---BUFFER DUMP follows---\n");
   if (debug_fd > 0) {
      snprintf(outbuf, sizeof(outbuf) ,"---BUFFER DUMP follows---\n");
      write(debug_fd, outbuf, strlen(outbuf));
   }

   for (i=0; i<length; i+=16) {
      strcpy(tmplin1,"");
      strcpy(tmplin2,"");
      for (j=0;(j<16) && (i+j)<length ;j++) {
         sprintf(tmp,"%2.2x ",(unsigned char)buffer[i+j]);
         strcat(tmplin1, tmp);
         sprintf(tmp, "%c",(isprint((int)buffer[i+j]))? buffer[i+j]: '.');
         strcat(tmplin2, tmp);
      }
      if (log_to_stderr) {
         fprintf(stderr, "  %-47.47s %-16.16s\n",tmplin1, tmplin2);
      }
      if (debug_fd > 0) {
         snprintf(outbuf, sizeof(outbuf) ,"  %-47.47s %-16.16s\n",
                  tmplin1, tmplin2);
         write(debug_fd, outbuf, strlen(outbuf));
      }
   }

   if (log_to_stderr) {
      fprintf(stderr,"\n---end of BUFFER DUMP---\n");
      fflush(stderr);
   }
   if (debug_fd > 0) {
      snprintf(outbuf, sizeof(outbuf) ,"---end of BUFFER DUMP---\n");
      write(debug_fd, outbuf, strlen(outbuf));
   }
   pthread_mutex_unlock(&log_mutex);

   return;
}

