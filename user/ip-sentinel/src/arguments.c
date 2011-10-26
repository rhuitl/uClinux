// $Id: arguments.c,v 1.16 2005/03/08 00:01:44 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003,2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//  
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//  

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "arguments.h"
#include "util.h"

#include <getopt.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>

#ifndef DEFAULT_IPFILE
#  define DEFAULT_IPFILE		PATH_CONFIGFILE
#endif

#ifndef DEFAULT_PIDFILE
#  define DEFAULT_PIDFILE		"/var/run/ip-sentinel.run"
#endif

#ifndef DEFAULT_LOGFILE
#  define DEFAULT_LOGFILE		"/var/log/ip-sentinel.out"
#endif

#ifndef DEFAULT_ERRFILE
#  define DEFAULT_ERRFILE		"/var/log/ip-sentinel.err"
#endif

#ifndef DEFAULT_USER
#  define DEFAULT_USER			SENTINEL_USER
#endif

#ifndef DEFAULT_GROUP
#  define DEFAULT_GROUP			SENTINEL_USER
#endif

#ifndef DEFAULT_CHROOT
#  define DEFAULT_CHROOT		0
#endif


#define OPTION_MAC			1024
#define OPTION_LLMAC			1025
#define OPTION_DIRECTION		1026
#define OPTION_POISON			1027

static struct option
cmdline_options[] = {
  { "ipfile",    required_argument, 0, 'i' },
  { "pidfile",   required_argument, 0, 'p' },
  { "logfile",   required_argument, 0, 'l' },
  { "errfile",   required_argument, 0, 'e' },
  { "user",      required_argument, 0, 'u' },
  { "group",     required_argument, 0, 'g' },
  { "nofork",    no_argument,       0, 'n' },
  { "chroot",    required_argument, 0, 'r' },
  { "help",      no_argument,       0, 'h' },
  { "version",   no_argument,       0, 'v' },
  { "action",    required_argument, 0, 'a' },
  { "mac",       required_argument, 0, OPTION_MAC },
  { "llmac",     required_argument, 0, OPTION_LLMAC },
  { "direction", required_argument, 0, OPTION_DIRECTION },
  { "poison",    no_argument,       0, OPTION_POISON },
  { 0, 0, 0, 0 }
};

static void
printHelp(char const *cmd, int fd)
{
  WRITE_MSGSTR(fd, "ip-sentinel " PACKAGE_VERSION " -- keeps your ip-space clean\n\nUsage: \n   ");
  WRITE_MSG   (fd, cmd);
  WRITE_MSGSTR(fd,
	       " [--ipfile|-i <FILE>] [--pidfile|-p <FILE>]\n"
	       "        [--logfile|-l <FILE>] [--errfile|-e <FILE>]"
	       " [--user|-u <USER>]\n"
   	       "        [--chroot|-r <DIR>] [--nofork|-n] [--mac MAC] \n"
	       "        [--help|-h] [--version] <interface>\n"
	       "\n"
	       "      --ipfile|-i <FILE>      read blocked IPs from FILE [" DEFAULT_IPFILE "]\n"
	       "                              within CHROOT\n"
	       "      --pidfile|-p <FILE>     write daemon-pid into FILE\n"
	       "                              [" DEFAULT_PIDFILE "]\n"
	       "      --logfile|-l <FILE>     log activities into FILE\n"
	       "                              [" DEFAULT_LOGFILE "]\n"
	       "      --errfile|-e <FILE>     log errors into FILE\n"
	       "                              [" DEFAULT_ERRFILE "]\n"
	       "      --user|-u <USER>        run as user USER [" DEFAULT_USER "]\n"
	       "      --group|-g <GROUP>      run as group GROUP [gid of user]\n"
	       "      --chroot|-r <DIR>       go into chroot-jail at DIR [<HOME>]\n"
	       "      --nofork|-n             do not fork a daemon-process\n"
	       "      --mac <MAC>             use MAC as the default faked mac address;\n"
	       "                              possible values are LOCAL, RANDOM, 802.1d,\n"
	       "                              802.3x or a real mac [802.3x]\n"
	       "      --llmac <MAC>           use MAC as the default mac address in link-level\n"
	       "                              headers when answering requests *from* intruders;\n"
	       "                              additionally to the values described at '--mac',\n"
               "                              <MAC> can be 'SAME' which means that the mac from\n"
	       "                              the arp-header will be used. [LOCAL]\n"
	       "      --direction <DIR>       answer arp-requests going into the specified\n"
	       "                              direction (relative to the intruder) only.\n"
	       "                              Valid values are 'FROM', 'TO' and 'BOTH'. [BOTH]\n"
	       "      --poison                generate faked ARP-answers for an intruder's ip\n"
	       "                              address when *he* sends a request. Works only\n"
	       "                              in combination with '--direction FROM|BOTH'.\n"
	       "      --action <program>      execute <program> when faked replies will be\n"
	       "                              generated. This program will be called with 6\n"
	       "                              arguments: <type> <spa> <sha> <tpa> <tha> <mac>.\n"
	       "      --help|-h               display this text and exit\n"
	       "      --version               print version and exit\n"
	       "      interface               ethernet-interface where to listen\n"
	       "                              on ARP-requests\n"
	       "\nPlease report errors to <" PACKAGE_BUGREPORT ">\n");
}

static void
printVersion(int fd)
{
  WRITE_MSGSTR(fd,
	       "ip-sentinel " PACKAGE_VERSION " -- keeps your ip-space clean\n"
	       "Copyright 2002,2003 Enrico Scholz\n"
	       "This program is free software; you may redistribute it under the terms of\n"
	       "the GNU General Public License.  This program has absolutely no warranty.\n");
}

static void
Arguments_parseMac(char const *optarg, struct TaggedMac *mac, bool allow_same)
{
  if      (              strcmp(optarg, "RANDOM")==0) mac->type = mcRANDOM;
  else if (              strcmp(optarg, "LOCAL") ==0) mac->type = mcLOCAL;
  else if (allow_same && strcmp(optarg, "SAME")  ==0) mac->type = mcSAME;
  else {
    if (!xether_aton_r(optarg, &mac->addr.ether)) {
      WRITE_MSGSTR(2, "invalid mac specified\n");
      exit(1);
    }
    mac->type = mcFIXED;
  }
}

static void
Arguments_parseDirection(char const *optarg, struct Arguments *options)
{
  if      (strcmp(optarg, "FROM")==0) options->arp_dir = dirFROM;
  else if (strcmp(optarg, "TO")  ==0) options->arp_dir = dirTO;
  else if (strcmp(optarg, "BOTH")==0) options->arp_dir = dirBOTH;
  else {
    WRITE_MSGSTR(2, "invalid value for '--direction' specified\n");
    exit(1);
  }
}

void
parseOptions(int argc, char *argv[], struct Arguments *options)
{
  assert(options!=0);
  
  options->ipfile   = DEFAULT_IPFILE;
  options->pidfile  = DEFAULT_PIDFILE;
  options->logfile  = DEFAULT_LOGFILE;
  options->errfile  = DEFAULT_ERRFILE;
  options->user     = DEFAULT_USER;
  options->group    = 0;
  options->do_fork  = true;
  options->chroot   = 0;
  options->arp_dir  = dirBOTH;
  options->llmac.type = mcLOCAL;
  options->do_poison  = true;
  options->action_cmd = 0;

  Arguments_parseMac("802.3x", &options->mac, false);

  while (1) {
    int	c = getopt_long(argc, argv, "hi:p:l:e:u:g:nr:", cmdline_options, 0);
    if (c==-1) break;

    switch (c) {
      case 'h'  :  printHelp(argv[0],1); exit(0); break;
      case 'a'	:  options->action_cmd = optarg; break;
      case 'e'	:  options->errfile    = optarg; break;
      case 'g'	:  options->group      = optarg; break;
      case 'i'	:  options->ipfile     = optarg; break;
      case 'l'	:  options->logfile    = optarg; break;
      case 'p'	:  options->pidfile    = optarg; break;
      case 'r'	:  options->chroot     = optarg; break;
      case 'u'	:  options->user       = optarg; break;
      case 'n'	:  options->do_fork    = false;  break;
      case 'v'	:  printVersion(1); exit(0);   break;
      case OPTION_MAC		:  Arguments_parseMac(optarg, &options->mac,  false); break;
      case OPTION_LLMAC		:  Arguments_parseMac(optarg, &options->llmac, true); break;
      case OPTION_DIRECTION	:  Arguments_parseDirection(optarg, options);         break;
      case OPTION_POISON	:  options->do_poison = true; break;
	
      default	:
	WRITE_MSGSTR(2, "Try \"");
	WRITE_MSG   (2, argv[0]);
	WRITE_MSGSTR(2, " --help\" for more information.\n");
	exit(1);
	break;
    }
  }

  if      (optind>=argc)   WRITE_MSGSTR(2, "No interface specified; ");
  else if (optind+1!=argc) WRITE_MSGSTR(2, "Too much interfaces specified; ");

  if (optind+1!=argc) {
    WRITE_MSGSTR(2, "try \"");
    WRITE_MSG   (2, argv[0]);
    WRITE_MSGSTR(2, " --help\" for more information.\n");
    exit(1);
  }

  options->iface = argv[optind];
}

static void
fixupMac(struct TaggedMac *mac)
{
  if (mac->type==mcLOCAL) {
    (void)xether_aton_r("LOCAL", &mac->addr.ether);
    mac->type=mcFIXED;
  }
}

void
Arguments_fixupOptions(struct Arguments *options)
{
  fixupMac(&options->mac);
  fixupMac(&options->llmac);
}
