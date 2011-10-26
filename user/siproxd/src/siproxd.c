/* -*- Mode: C; c-basic-offset: 3 -*-
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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>

#ifdef  HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: siproxd.c,v 1.61 2005/04/16 09:30:55 hb9xar Exp $";

/* configuration storage */
struct siproxd_config configuration;

char *pidfilename;

/* Global File instance on pw file */
FILE *siproxd_passwordfile;

int createpidfile(char* pidfilename)
{
   FILE *f = NULL;
   DEBUGC(DBCLASS_CONFIG,"creating PID file [%s]", pidfilename);
   if ((f=fopen(pidfilename, "w")))
      {
         fprintf(f,"%i\n",(int)getpid());
         fclose(f);
      }
   else
      {
         WARN("couldn't create new PID file: %s", strerror(errno));
         return(1);
      }
   return(0);
}


/* -h help option text */
static const char str_helpmsg[] =
PACKAGE "-" VERSION "-" BUILDSTR " (c) 2002-2005 Thomas Ries\n"
"\nUsage: siproxd [options]\n\n"
"options:\n"
#ifdef  HAVE_GETOPT_LONG
"       -h, --help                 help\n"
"       -d, --debug <pattern>      set debug-pattern\n"
"       -c, --config <cfgfile>     use the specified config file\n"
"       -p, --pid-file <pidfile>   create pid file <pidfile>\n"
#else
"       -h              help\n"
"       -d <pattern>    set debug-pattern\n"
"       -c <cfgfile>    use the specified config file\n"
"       -p <pidfile>    create pid file <pidfile>\n"
#endif
"";



/*
 * module local data
 */
static  int dmalloc_dump=0;
static  int exit_program=0;

/*
 * local prototypes
 */
static void sighandler(int sig);


int main (int argc, char *argv[]) 
{
   int sts;
   int i;
   int buflen;
   int access;
   char buff [BUFFER_SIZE];
   sip_ticket_t ticket;

   extern char *optarg;         /* Defined in libc getopt and unistd.h */
   int ch1;
   
   char configfile[64]="siproxd";       /* basename of configfile */
   int  config_search=1;                /* search the config file */
   int  cmdline_debuglevel=0;
   struct sigaction act;

   log_set_stderr(1);

/*
 * setup signal handlers
 */
   act.sa_handler=sighandler;
   sigemptyset(&act.sa_mask);
   act.sa_flags=SA_RESTART;
   if (sigaction(SIGTERM, &act, NULL)) {
      ERROR("Failed to install SIGTERM handler");
   }
   if (sigaction(SIGINT, &act, NULL)) {
      ERROR("Failed to install SIGINT handler");
   }
   if (sigaction(SIGUSR2, &act, NULL)) {
      ERROR("Failed to install SIGUSR2 handler");
   }


/*
 * prepare default configuration
 */
   make_default_config();

   log_set_pattern(configuration.debuglevel);

/*
 * open a the pwfile instance, so we still have access after
 * we possibly have chroot()ed to somewhere.
 */
   if (configuration.proxy_auth_pwfile) {
      siproxd_passwordfile = fopen(configuration.proxy_auth_pwfile, "r");
   } else {
      siproxd_passwordfile = NULL;
   }

   // Open Log at beginning so it can still be accessed in the chroot
   openlog("siproxd",LOG_NDELAY|LOG_PID,LOG_DAEMON);
/*
 * parse command line
 */
{
#ifdef  HAVE_GETOPT_LONG
   int option_index = 0;
   static struct option long_options[] = {
      {"help", no_argument, NULL, 'h'},
      {"config", required_argument, NULL, 'c'},
      {"debug", required_argument, NULL, 'd'},
      {"pid-file", required_argument, NULL,'p'},
      {0,0,0,0}
   };

    while ((ch1 = getopt_long(argc, argv, "hc:d:p:",
                  long_options, &option_index)) != -1) {
#else   /* ! HAVE_GETOPT_LONG */
    while ((ch1 = getopt(argc, argv, "hc:d:p:")) != -1) {
#endif
      switch (ch1) {
      case 'h': /* help */
         DEBUGC(DBCLASS_CONFIG,"option: help");
         fprintf(stderr,str_helpmsg);
         exit(0);
         break;

      case 'c': /* load config file */
         DEBUGC(DBCLASS_CONFIG,"option: config file=%s",optarg);
         i=sizeof(configfile)-1;
         strncpy(configfile,optarg,i-1);
         configfile[i]='\0';
         config_search=0;
         break; 

      case 'd': /* set debug level */
         DEBUGC(DBCLASS_CONFIG,"option: set debug level: %s",optarg);
         cmdline_debuglevel=atoi(optarg);
         log_set_pattern(cmdline_debuglevel);
         break;

      case 'p':
         pidfilename = optarg;
         break;

      default:
         DEBUGC(DBCLASS_CONFIG,"no command line options");
         break; 
      }
   }
}

/*
 * Init stuff
 */
   INFO(PACKAGE"-"VERSION"-"BUILDSTR" "UNAME" starting up");

   /* read the config file */
   if (read_config(configfile, config_search) == STS_FAILURE) exit(1);

   /* if a debug level > 0 has been given on the commandline use its
      value and not what is in the config file */
   if (cmdline_debuglevel != 0) {
      configuration.debuglevel=cmdline_debuglevel;
   }

   /* set debug level as desired */
   log_set_pattern(configuration.debuglevel);
   log_set_listen_port(configuration.debugport);

   /* daemonize if requested to */
   if (configuration.daemonize) {
      DEBUGC(DBCLASS_CONFIG,"daemonizing");
      if (fork()!=0) exit(0);
      setsid();
      if (fork()!=0) exit(0);

      log_set_stderr(0);
      INFO("daemonized, pid=%i", getpid());
      /* change user, group and chroot */
      secure_enviroment();
      
   }
   else
      secure_enviroment();

   /* write PID file of main thread */
   if ((configuration.pid_file) && (!pidfilename))
      createpidfile(configuration.pid_file);
   
   /* Start the RTP proxy */
   sts=rtpproxy_init();
   if (sts != STS_SUCCESS) {
      ERROR("unable to initialize RTP proxy - aborting"); 
      exit(1);
   }

   /* init the oSIP parser */
   parser_init();

   /* listen for incoming messages */
   sts=sipsock_listen();
   if (sts == STS_FAILURE) {
      /* failure to allocate SIP socket... */
      ERROR("unable to bind to SIP listening socket - aborting"); 
      exit(1);
   }

   /* initialize the registration facility */
   register_init();

/*
 * silence the log - if so required...
 */
   log_set_silence(configuration.silence_log);

   INFO(PACKAGE"-"VERSION"-"BUILDSTR" "UNAME" started");

/*
 * Main loop
 */
   while (!exit_program) {

      DEBUGC(DBCLASS_BABBLE,"going into sipsock_wait\n");
      while (sipsock_wait()<=0) {
         /* got no input, here by timeout. do aging */
         register_agemap();

         /* TCP log: check for a connection */
         log_tcp_connect();

         /* dump memory stats if requested to do so */
         if (dmalloc_dump) {
            dmalloc_dump=0;
#ifdef DMALLOC
            INFO("SIGUSR2 - DMALLOC statistics is dumped");
            dmalloc_log_stats();
            dmalloc_log_unfreed();
#else
            INFO("SIGUSR2 - DMALLOC support is not compiled in");
#endif
         }

         if (exit_program) goto exit_prg;
      }

      /* got input, process */
      DEBUGC(DBCLASS_BABBLE,"back from sipsock_wait");

      buflen=sipsock_read(&buff, sizeof(buff)-1, &ticket.from,
                           &ticket.protocol);
      buff[buflen]='\0';

      /* evaluate the access lists (IP based filter)*/
      access=accesslist_check(ticket.from);
      if (access == 0) {
         DEBUGC(DBCLASS_ACCESS,"access for this packet was denied");
         continue; /* there are no resources to free */
      }

      /* integrity checks */
      sts=security_check_raw(buff, buflen);
      if (sts != STS_SUCCESS) {
         DEBUGC(DBCLASS_SIP,"security check (raw) failed");
         continue; /* there are no resources to free */
      }

      /* init sip_msg */
      sts=osip_message_init(&ticket.sipmsg);
      ticket.sipmsg->message=NULL;
      if (sts != 0) {
         ERROR("osip_message_init() failed... this is not good");
         continue; /* skip, there are no resources to free */
      }

      /*
       * RFC 3261, Section 16.3 step 1
       * Proxy Behavior - Request Validation - Reasonable Syntax
       * (parse the received message)
       */
      sts=sip_message_parse(ticket.sipmsg, buff, buflen);
      if (sts != 0) {
         ERROR("sip_message_parse() failed... this is not good");
         DUMP_BUFFER(-1, buff, buflen);
         goto end_loop; /* skip and free resources */
      }

      /* integrity checks - parsed buffer*/
      sts=security_check_sip(&ticket);
      if (sts != STS_SUCCESS) {
         ERROR("security_check_sip() failed... this is not good");
         DUMP_BUFFER(-1, buff, buflen);
         goto end_loop; /* skip and free resources */
      }

      /*
       * RFC 3261, Section 16.3 step 2
       * Proxy Behavior - Request Validation - URI scheme
       * (check request URI and refuse with 416 if not understood)
       */
      /* NOT IMPLEMENTED */

      /*
       * RFC 3261, Section 16.3 step 3
       * Proxy Behavior - Request Validation - Max-Forwards check
       * (check Max-Forwards header and refuse with 483 if too many hops)
       */
      {
      osip_header_t *max_forwards;
      int forwards_count = DEFAULT_MAXFWD;

      osip_message_get_max_forwards(ticket.sipmsg, 0, &max_forwards);
      if (max_forwards && max_forwards->hvalue) {
         forwards_count = atoi(max_forwards->hvalue);
      }

      DEBUGC(DBCLASS_PROXY,"checking Max-Forwards (=%i)",forwards_count);
      if (forwards_count <= 0) {
         DEBUGC(DBCLASS_SIP, "Forward count reached 0 -> 483 response");
         sip_gen_response(&ticket, 483 /*Too many hops*/);
         goto end_loop; /* skip and free resources */
      }

      }

      /*
       * RFC 3261, Section 16.3 step 4
       * Proxy Behavior - Request Validation - Loop Detection check
       * (check for loop and return 482 if a loop is detected)
       */
      if (check_vialoop(&ticket) == STS_TRUE) {
         /* make sure we don't end up in endless loop when detecting
          * an loop in an "loop detected" message - brrr */
         if (MSG_IS_RESPONSE(ticket.sipmsg) && 
             MSG_TEST_CODE(ticket.sipmsg, 482)) {
            DEBUGC(DBCLASS_SIP,"loop in loop-response detected, ignoring");
         } else {
            DEBUGC(DBCLASS_SIP,"via loop detected, ignoring request");
            sip_gen_response(&ticket, 482 /*Loop detected*/);
         }
         goto end_loop; /* skip and free resources */
      }

      /*
       * RFC 3261, Section 16.3 step 5
       * Proxy Behavior - Request Validation - Proxy-Require check
       * (check Proxy-Require header and return 420 if unsupported option)
       */
      /* NOT IMPLEMENTED */

      /*
       * RFC 3261, Section 16.5
       * Proxy Behavior - Determining Request Targets
       */
      /* NOT IMPLEMENTED */

      DEBUGC(DBCLASS_SIP,"received SIP type %s:%s",
             (MSG_IS_REQUEST(ticket.sipmsg))? "REQ" : "RES",
             (MSG_IS_REQUEST(ticket.sipmsg) ?
                ((ticket.sipmsg->sip_method)?
                   ticket.sipmsg->sip_method : "NULL") :
                ((ticket.sipmsg->reason_phrase) ? 
                   ticket.sipmsg->reason_phrase : "NULL")));
              
      /*
       * if an REQ REGISTER, check if it is directed to myself,
       * or am I just the outbound proxy but no registrar.
       * - If I'm the registrar, register & generate answer
       * - If I'm just the outbound proxy, register, rewrite & forward
       */
      if (MSG_IS_REGISTER(ticket.sipmsg) && 
          MSG_IS_REQUEST(ticket.sipmsg)) {
         if (access & ACCESSCTL_REG) {
            osip_uri_t *url;
            struct in_addr addr1, addr2, addr3;
            int dest_port;

            url = osip_message_get_uri(ticket.sipmsg);
            dest_port= (url->port)?atoi(url->port):SIP_PORT;

            if ( (get_ip_by_host(url->host, &addr1) == STS_SUCCESS) &&
                 (get_interface_ip(IF_INBOUND,&addr2) == STS_SUCCESS) &&
                 (get_interface_ip(IF_OUTBOUND,&addr3) == STS_SUCCESS)) {

               if ((configuration.sip_listen_port == dest_port) &&
                   ((memcmp(&addr1, &addr2, sizeof(addr1)) == 0) ||
                    (memcmp(&addr1, &addr3, sizeof(addr1)) == 0))) {
                  /* I'm the registrar, send response myself */
                  sts = register_client(&ticket, 0);
                  sts = register_response(&ticket, sts);
               } else {
                  /* I'm just the outbound proxy */
                  DEBUGC(DBCLASS_SIP,"proxying REGISTER request to:%s",
                         url->host);
                  sts = register_client(&ticket, 1);
                  sts = proxy_request(&ticket);
               }
            } else {
               if (MSG_IS_REQUEST(ticket.sipmsg)) {
                  sip_gen_response(&ticket, 408 /*request timeout*/);
               }
            }
         } else {
            WARN("non-authorized registration attempt from %s",
                 utils_inet_ntoa(ticket.from.sin_addr));
         }

      /*
       * check if outbound interface is UP.
       * If not, send back error to UA and
       * skip any proxying attempt
       */
      } else if (get_interface_ip(IF_OUTBOUND,NULL) !=
                 STS_SUCCESS) {
         DEBUGC(DBCLASS_SIP, "got a %s to proxy, but outbound interface "
                "is down", (MSG_IS_REQUEST(ticket.sipmsg))? "REQ" : "RES");

         if (MSG_IS_REQUEST(ticket.sipmsg))
            sip_gen_response(&ticket, 408 /*request timeout*/);
      
      /*
       * MSG is a request, add current via entry,
       * do a lookup in the URLMAP table and
       * send to the final destination
       */
      } else if (MSG_IS_REQUEST(ticket.sipmsg)) {
         if (access & ACCESSCTL_SIP) {
            sts = proxy_request(&ticket);
         } else {
            INFO("non-authorized request received from %s",
                 utils_inet_ntoa(ticket.from.sin_addr));
         }

      /*
       * MSG is a response, remove current via and
       * send to the next VIA in chain
       */
      } else if (MSG_IS_RESPONSE(ticket.sipmsg)) {
         if (access & ACCESSCTL_SIP) {
            sts = proxy_response(&ticket);
         } else {
            INFO("non-authorized response received from %s",
                 utils_inet_ntoa(ticket.from.sin_addr));
         }
         
      /*
       * unsupported message
       */
      } else {
         ERROR("received unsupported SIP type %s %s",
               (MSG_IS_REQUEST(ticket.sipmsg))? "REQ" : "RES",
               ticket.sipmsg->sip_method);
      }


/*
 * free the SIP message buffers
 */
      end_loop:
      osip_message_free(ticket.sipmsg);

   } /* while TRUE */
   exit_prg:

   /* save current known SIP registrations */
   register_save();
   INFO("properly terminating siproxd");

   /* remove PID file */
   if (pidfilename) {
      DEBUGC(DBCLASS_CONFIG,"deleting PID file [%s]", pidfilename);
      sts=unlink(pidfilename);
      if (sts != 0) {
         WARN("couldn't delete old PID file: %s", strerror(errno));
      }
   }

   /* END */
   return 0;
} /* main */

/*
 * Signal handler
 *
 * this one is called asynchronously whevener a registered
 * signal is applied. Just set a flag and don't do any funny
 * things here.
 */
static void sighandler(int sig) {
   if (sig==SIGTERM) exit_program=1;
   if (sig==SIGINT)  exit_program=1;
   if (sig==SIGUSR2) dmalloc_dump=1;
   return;
}
