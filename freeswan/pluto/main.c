/* Pluto main program
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <getopt.h>
#include <resolv.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "connections.h"	/* needs id.h */
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "server.h"
#include "kernel.h"
#include "log.h"
#include "x509.h"
#include "preshared.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs preshared.h and adns.h */
#include "rnd.h"
#include "state.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h"	/* requires sha1.h and md5.h */

#ifdef VIRTUAL_IP
#include "virtual.h"
#endif

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

char *phys_interfaces[NUM_INTERFACES];

/*
 *  Version of X.509 patch
 */
static const char x509patch_version[] = "0.9.13";

static void
usage(const char *mess)
{
    if (mess != NULL && *mess != '\0')
	fprintf(stderr, "%s\n", mess);
    fprintf(stderr,
	"Usage: pluto"
	    " [--help]"
	    " [--version]"
	    " [--optionsfrom <filename>]"
	    " \\\n\t"
	    "[--nofork]"
	    " [--stderrlog]"
	    " [--noklips]"
	    " [--nocrsend]"
	    " [--uniqueids]"
	    " \\\n\t"
	    "[--interface <ifname>]"
	    " [--ikeport <port-number>]"
	    " \\\n\t"
	    "[--ctlbase <path>]"
	    " \\\n\t"
	    "[--secretsfile <secrets-file>]"
	    " \\\n\t"
	    "[--adns <pathname>]"
#ifdef DEBUG
	    " \\\n\t"
	    "[--debug-none]"
	    " [--debug-all]"
	    " \\\n\t"
	    "[--debug-raw]"
	    " [--debug-crypt]"
	    " [--debug-parsing]"
	    " [--debug-emitting]"
	    " \\\n\t"
	    "[--debug-control]"
	    " [--debug-klips]"
	    " [--debug-dns]"
	    " [ --debug-private]"
#endif
#ifdef NAT_TRAVERSAL
	    " [ --debug-nat_t]"
	    " \\\n\t"
	    "[--nat_traversal] [--keep_alive <delay_sec>]"
	    " \\\n\t"
		"[--force_keepalive] [--disable_port_floating]"
#endif
#ifdef VIRTUAL_IP
	    " \\\n\t"
	    "[--virtual_private <network_list>]"
#endif
	    "\n"
	"FreeS/WAN %s\n",
	ipsec_version_code());
    exit_pluto(mess == NULL? 0 : 1);
}

static void init_interfaces( char *ipsec0, char *ipsec1, char *ipsec2, char *ipsec3)
{
	if (ipsec0)
		phys_interfaces[0] = strdup(ipsec0);
	if (ipsec1)
		phys_interfaces[1] = strdup(ipsec1);
	if (ipsec2)
		phys_interfaces[2] = strdup(ipsec2);
	if (ipsec3)
		phys_interfaces[3] = strdup(ipsec3);
}

/* lock file support
 * - provides convenient way for scripts to find Pluto's pid
 * - prevents multiple Plutos competing for the same port
 * - same basename as unix domain control socket
 * NOTE: will not take account of sharing LOCK_DIR with other systems.
 */

static char pluto_lock[sizeof(ctl_addr.sun_path)] = DEFAULT_CTLBASE LOCK_SUFFIX;
static bool pluto_lock_created = FALSE;

/* create lockfile, or die in the attempt */
static int
create_lock(void)
{
    int fd = open(pluto_lock, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
	S_IRUSR | S_IRGRP | S_IROTH);

    if (fd < 0)
    {
	if (errno == EEXIST)
	{
	    fprintf(stderr, "pluto: lock file \"%s\" already exists\n"
		, pluto_lock);
	    exit_pluto(10);
	}
	else
	{
	    fprintf(stderr
		, "pluto: unable to create lock file \"%s\" (%d %s)\n"
		, pluto_lock, errno, strerror(errno));
	    exit_pluto(1);
	}
    }
    pluto_lock_created = TRUE;
    return fd;
}

static bool
fill_lock(int lockfd, pid_t pid)
{
    char buf[30];	/* holds "<pid>\n" */
    int len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int) pid);
    bool ok = len > 0 && write(lockfd, buf, len) == len;

    close(lockfd);
    return ok;
}

static void
delete_lock(void)
{
    if (pluto_lock_created)
    {
	delete_ctl_socket();
	unlink(pluto_lock);	/* is noting failure useful? */
    }
}

/* by default pluto sends certificate requests to its peers */
bool no_cr_send = FALSE;

int
main(int argc, char **argv)
{
    bool fork_desired = TRUE;
    bool log_to_stderr_desired = FALSE;
    int lockfd;
#ifdef NAT_TRAVERSAL
    bool nat_traversal = FALSE;
    bool nat_t_spf = TRUE;  /* support port floating */
    unsigned int keep_alive = 0;
    bool force_keepalive = FALSE;
#endif
#ifdef VIRTUAL_IP
    char *virtual_private = NULL;
#endif

    char *ipsec0 = NULL;
    char *ipsec1 = NULL;
    char *ipsec2 = NULL;
    char *ipsec3 = NULL;
    
    /* handle arguments */
    for (;;)
    {
	static const struct option long_opts[] = {
	    /* name, has_arg, flag, val */
	    { "help", no_argument, NULL, 'h' },
	    { "version", no_argument, NULL, 'v' },
	    { "optionsfrom", required_argument, NULL, '+' },
	    { "nofork", no_argument, NULL, 'd' },
	    { "stderrlog", no_argument, NULL, 'e' },
	    { "noklips", no_argument, NULL, 'n' },
	    { "nocrsend", no_argument, NULL, 'c' },
	    { "uniqueids", no_argument, NULL, 'u' },
	    { "interface", required_argument, NULL, 'i' },
	    { "ikeport", required_argument, NULL, 'p' },
	    { "ctlbase", required_argument, NULL, 'b' },
	    { "secretsfile", required_argument, NULL, 's' },
	    { "adns", required_argument, NULL, 'a' },
#ifdef DEBUG
	    { "debug-none", no_argument, NULL, 'N' },
	    { "debug-all]", no_argument, NULL, 'A' },
	    { "debug-raw", no_argument, NULL, 'R' },
	    { "debug-crypt", no_argument, NULL, 'X' },
	    { "debug-parsing", no_argument, NULL, 'P' },
	    { "debug-emitting", no_argument, NULL, 'E' },
	    { "debug-control", no_argument, NULL, 'C' },
	    { "debug-lifecycle", no_argument, NULL, 'L' },
	    { "debug-klips", no_argument, NULL, 'K' },
	    { "debug-dns", no_argument, NULL, 'D' },
	    { "debug-private", no_argument, NULL, 'Z' },
#endif
#ifdef NAT_TRAVERSAL
	    { "nat_traversal", no_argument, NULL, '1' },
	    { "keep_alive", required_argument, NULL, '2' },
	    { "force_keepalive", no_argument, NULL, '3' },
	    { "disable_port_floating", no_argument, NULL, '4' },
	    { "debug-nat_t", no_argument, NULL, '5' },
#endif
#ifdef VIRTUAL_IP
	    { "virtual_private", required_argument, NULL, '6' },
#endif
    	    { "ipsec0", required_argument, NULL, '7' },
	    { "ipsec1", required_argument, NULL, '8' },
	    { "ipsec2", required_argument, NULL, '9' },
	    { "ipsec3", required_argument, NULL, '0' },
	    { 0,0,0,0 }
	    };
	/* Note: we don't like the way short options get parsed
	 * by getopt_long, so we simply pass an empty string as
	 * the list.  It could be "hvdenp:l:s:" "NARXPECK".
	 */
	int c = getopt_long(argc, argv, "", long_opts, NULL);

	/* Note: "breaking" from case terminates loop */
	switch (c)
	{
	case EOF:	/* end of flags */
	    break;

	case 0: /* long option already handled */
	    continue;

	case ':':	/* diagnostic already printed by getopt_long */
	case '?':	/* diagnostic already printed by getopt_long */
	    usage("");
	    break;   /* not actually reached */

	case 'h':	/* --help */
	    usage(NULL);
	    break;	/* not actually reached */

	case 'v':	/* --version */
	    {
		const char **sp = ipsec_copyright_notice();

		printf("%s\n", ipsec_version_string());
		for (; *sp != NULL; sp++)
		    puts(*sp);
	    }
	    exit_pluto(0);
	    break;	/* not actually reached */

	case '+':	/* --optionsfrom <filename> */
	    optionsfrom(optarg, &argc, &argv, optind, stderr);
	    /* does not return on error */
	    continue;

	case 'd':	/* --nofork*/
	    fork_desired = FALSE;
	    continue;

	case 'e':	/* --stderrlog */
	    log_to_stderr_desired = TRUE;
	    continue;

	case 'n':	/* --noklips */
	    no_klips = TRUE;
	    continue;

	case 'c':	/* --nocrsend */
	    no_cr_send = TRUE;
	    continue
	    ;
	case 'u':	/* --uniquids */
	    uniqueIDs = TRUE;
	    continue;

	case 'i':	/* --interface <ifname> */
	    if (!use_interface(optarg))
		usage("too many --interface specifications");
	    continue;

	case 'p':	/* --port <portnumber> */
	    if (optarg == NULL || !isdigit(optarg[0]))
		usage("missing port number");

	    {
		char *endptr;
		long port = strtol(optarg, &endptr, 0);

		if (*endptr != '\0' || endptr == optarg
		|| port <= 0 || port > 0x10000)
		    usage("<port-number> must be a number between 1 and 65535");
		pluto_port = port;
	    }
	    continue;

	case 'b':	/* --ctlbase <path> */
	    if (snprintf(ctl_addr.sun_path, sizeof(ctl_addr.sun_path)
	    , "%s%s", optarg, CTL_SUFFIX) == -1)
		usage("<path>" CTL_SUFFIX " too long for sun_path");
	    if (snprintf(pluto_lock, sizeof(pluto_lock)
	    , "%s%s", optarg, LOCK_SUFFIX) == -1)
		usage("<path>" LOCK_SUFFIX " must fit");
	    continue;

	case 's':	/* --secretsfile <secrets-file> */
	    shared_secrets_file = optarg;
	    continue;

	case 'a':	/* --adns <pathname> */
	    pluto_adns_option = optarg;
	    continue;

#ifdef DEBUG
	case 'N':	/* --debug-none */
	    base_debugging = DBG_NONE;
	    continue;

	case 'A':	/* --debug-all */
	    base_debugging = DBG_ALL;
	    continue;

	case 'R':	/* --debug-raw */
	    base_debugging |= DBG_RAW;
	    continue;

	case 'X':	/* --debug-crypt */
	    base_debugging |= DBG_CRYPT;
	    continue;

	case 'P':	/* --debug-parsing */
	    base_debugging |= DBG_PARSING;
	    continue;

	case 'E':	/* --debug-emitting */
	    base_debugging |= DBG_EMITTING;
	    continue;

	case 'C':	/* --debug-control */
	    base_debugging |= DBG_CONTROL;
	    continue;

	case 'L':	/* --debug-lifecycle */
	    base_debugging |= DBG_LIFECYCLE;
	    continue;

	case 'K':	/* --debug-klips */
	    base_debugging |= DBG_KLIPS;
	    continue;

	case 'D':	/* --debug-dns */
	    base_debugging |= DBG_DNS;
	    continue;

	case 'Z':	/* --debug-private */
	    base_debugging |= DBG_PRIVATE;
	    continue;
#endif
#ifdef NAT_TRAVERSAL
	case '1':	/* --nat_traversal */
	    nat_traversal = TRUE;
	    continue;
	case '2':	/* --keep_alive */
	    keep_alive = atoi(optarg);
	    continue;
	case '3':	/* --force_keepalive */
	    force_keepalive = TRUE;
	    continue;
	case '4':	/* --disable_port_floating */
	    nat_t_spf = FALSE;
	    continue;
	case '5':	/* --debug-nat_t */
	    base_debugging |= DBG_NATT;
	    continue;
#endif
#ifdef VIRTUAL_IP
	case '6':	/* --virtual_private */
	    virtual_private = optarg;
	    continue;
#endif
	case '7':	/* --ipsec0 */
	    ipsec0 = optarg;
	    continue;
	case '8':	/* --ipsec1 */
	    ipsec1 = optarg;
	    continue;
	case '9':	/* --ipsec2 */
	    ipsec2 = optarg;
	    continue;
	case '0':	/* --ipsec3 */
	    ipsec3 = optarg;
	    continue;

	default:
	    impossible();
	}
	break;
    }
    if (optind != argc)
	usage("unexpected argument");
    reset_debugging();
    lockfd = create_lock();

    /* select between logging methods */

    if (log_to_stderr_desired)
	log_to_syslog = FALSE;
    else
	log_to_stderr = FALSE;

    /* create control socket.
     * We must create it before the parent process returns so that
     * there will be no race condition in using it.  The easiest
     * place to do this is before the daemon fork.
     */
    {
	err_t ugh = init_ctl_socket();

	if (ugh != NULL)
	{
	    fprintf(stderr, "pluto: %s", ugh);
	    exit_pluto(1);
	}
    }

    /* If not suppressed, do daemon fork */

#ifndef __uClinux__
    if (fork_desired)
    {
	{
	    pid_t pid = fork();

	    if (pid < 0)
	    {
		int e = errno;

		fprintf(stderr, "pluto: fork failed (%d %s)\n",
		    errno, strerror(e));
		exit_pluto(1);
	    }

	    if (pid != 0)
	    {
		/* parent: die, after filling PID into lock file.
		 * must not use exit_pluto: lock would be removed!
		 */
		exit(fill_lock(lockfd, pid)? 0 : 1);
	    }
	}

	if (setsid() < 0)
	{
	    int e = errno;

	    fprintf(stderr, "setsid() failed in main(). Errno %d: %s\n",
		errno, strerror(e));
	    exit_pluto(1);
	}

	/* Close everything but ctl_fd and (if needed) stderr. */
	{
	    int i;

	    for (i = getdtablesize() - 1; i >= 0; i--)  /* Bad hack */
		if ((!log_to_stderr || i != 2)
		&& i != ctl_fd)
		    close(i);

	    /* make sure that stdin, stdout, stderr are reserved */
	    if (open("/dev/null", O_RDONLY) != 0)
		abort();
	    if (dup2(0, 1) != 1)
		abort();
	    if (!log_to_stderr && dup2(0, 2) != 2)
		abort();
	}
    }
    else
#endif
    {
#ifdef __uClinux__
	if (fork_desired)
	{
	    setpgrp();
	}
#endif
	/* no daemon fork: we have to fill in lock file */
	(void) fill_lock(lockfd, getpid());
	fprintf(stdout, "Pluto initialized\n");
	fflush(stdout);
    }

    init_constants();
    init_log();
    /* Note: some scripts may look for this exact message -- don't change */
    log("Starting Pluto (FreeS/WAN Version %s)", ipsec_version_code());
    log("  including X.509 patch (Version %s)", x509patch_version);

#ifdef NAT_TRAVERSAL
    init_nat_traversal(nat_traversal, keep_alive, force_keepalive, nat_t_spf);
#endif

#ifdef VIRTUAL_IP
    init_virtual_ip(virtual_private);
#endif
    init_interfaces(ipsec0, ipsec1, ipsec2, ipsec3);
    init_rnd_pool();
    init_secret();
    init_states();
    init_crypto();
    init_demux();
    init_kernel();
    init_adns();

    /* loading CA certificates */
    load_cacerts();
    /* loading CRLs */
    load_crls();
    /* loading my X.509 or OpenPGP certificate */
    load_mycert();

    call_server();
    return -1;        /* Shouldn't ever reach this */
}

/* leave pluto, with status.
 * Once child is launched, parent must not exit this way because
 * the lock would be released.
 *
 *  0 OK
 *  1 general discomfort
 * 10 lock file exists
 */
void
exit_pluto(int status)
{
    reset_globals();	/* needed because we may be called in odd state */
    free_preshared_secrets();
    free_remembered_public_keys();
    delete_every_connection();
    free_cacerts();	/* free chain of CA certificates */
    free_crls();	/* free chain of CRLS */
    free_mycert();	/* free default certificate (deprecated for X.509) */
    free_ifaces();
    stop_adns();
    free_md_pool();
    delete_lock();
#ifdef LEAK_DETECTIVE
    report_leaks();
#endif /* LEAK_DETECTIVE */
    close_log();
    exit(status);
}
