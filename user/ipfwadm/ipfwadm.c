/*
 *	$Id: ipfwadm.c,v 1.6 2002-03-06 01:51:11 gerg Exp $
 *
 *
 *	ipfwadm -- IP firewall and accounting administration
 *
 *	See the accompanying manual page ipfwadm(8) for information
 *	about proper usage of this program.
 *
 *
 *	Copyright (c) 1995,1996 by X/OS Experts in Open Systems BV.
 *	All rights reserved.
 *
 *	Author: Jos Vos <jos@xos.nl>
 *
 *		X/OS Experts in Open Systems BV
 *		Kruislaan 419
 *		NL-1098 VA  Amsterdam
 *		The Netherlands
 *
 *		E-mail: info@xos.nl
 *		WWW:    http://www.xos.nl/
 *
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 *	Change history:
 *	1.1	First release of ipfwadm, which works in combination
 *		with Linux 1.2.1.
 *	1.2	Various changes in error messages, print format, comment.
 *	1.3	Add colon to 'p' in getopt string.
 *		Correct bug in printing range of destination port.
 *	1.4	Change the usage messages and add a large help text for -h.
 *	1.5	Change code to make "gcc -Wall" happy (and a few of these
 *		warnings were really serious ...).
 *	1.6	Port to 1.3.x Linux kernel (1.3.57 as reference).
 *		Rename -k option to -o (kernel packet logging).
 *		Support new TCPACK option with new -k option.
 *		Add support for masquerading rules (policy added).
 *		List active masquerading entries (via -M flag).
 *	1.7	Add some extra command/option checks and fix some typos.
 *		Allow specification of ICMP types (given as port numbers) and
 *		show source port numbers (ICMP types) when listing ICMP rules.
 *		Eliminate warnings due to new 1.3.x. IP-related include files.
 *	1.8	Major changes:
 *		Support separate input/output chains, socket option renaming,
 *		new -t flag for specifying TOS masks, and more...
 *		Works (only!) on Linux 1.3.61 and higher.
 *	1.9	Support matching with interface names (using option -W).
 *	1.10	Change layout of listing of active masqueraded sessions.
 *		Port to AXP (64-bit issues), untested.
 *	1.11	Fix bugs introduced in 1.10.
 *		[ipfwadm 2.0]
 *	1.12	Add support for port redirection (for supporting transparent
 *		proxying) via the -r flag.
 *		Support input/output only accounting rules by recognizing
 *		a direction (in/out/both) after the -A flag.
 *		Add -m option to use masquerading with policy accept
 *		(as a replacement of the masquerade policy, which is still
 *		supported for backwards compatibility).
 *		Slightly change the layout of the rule listings.
 *		Remove check for TCP protocol when using -k or -y.
 *	1.13	Also support kernels 1.3.66 up to 1.99.6 (untested).
 *		Check on missing command.
 *		[ipfwadm 2.1]
 *	1.14	Add <errno.h> to make new compile environments happy.
 *		Allow -r without a port number (use 0 as default value).
 *		Add -s command for setting timeout values (masquerading).
 *		[ipfwadm 2.2]
 *	1.15	Fill in packet length when checking packets (-c command).
 *		Do getnetbyname() before gethostbyname() to avoid DNS
 *		lookups (and timeouts) when specifying a known network name.
 *		Make "0.0.0.0/0" the default value for the -S and -D options,
 *		except when used in combination with the -c (check) command.
 *		Enforce correct use of the -W option (required for checking).
 *		Ignore the hostname when specifying a zero-mask, so that
 *		"any/0" (or whatever) can be used to specify "any" address.
 *		Include <sys/param.h> instead of <asm/param.h> and use HZ
 *		instead of 100 when reading the masquerading timeout values.
 *		[ipfwadm 2.3.0]
 *		
 */

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#define	__USE_MISC
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#define __u32 u_int32_t
#define __u16 u_int16_t
#include <netinet/ip_fw.h>
#include <sys/param.h>

#ifndef	IP_FW_F_REDIR
#define IPFWADM_NO_REDIR
#define IP_FW_F_REDIR		0
#endif	/* ! IP_FW_F_REDIR */

#if	!defined(IP_FW_F_ACCTIN) || !defined(IP_FW_F_ACCTOUT)
#define IPFWADM_NO_ACCTDIR
#define IP_FW_F_ACCTIN		0
#define IP_FW_F_ACCTOUT		0
#endif	/* ! IP_FW_F_REDIR */

#ifndef	IP_FW_MASQ_TIMEOUTS
#define IPFWADM_NO_TIMEOUT
#define IP_FW_MASQ_TIMEOUTS	0
#endif	/* ! IP_FW_MASQ_TIMEOUTS */

#define IP_VERSION	4
#define IP_OFFSET	0x1FFF

#define CHN_NONE	-1
#define CHN_FWD		0
#define CHN_IN		1
#define CHN_OUT		2
#define CHN_ACCT	3
#define CHN_MASQ	4	/* only used for listing masquerading */

#define CMD_NONE	0x0000
#define CMD_LIST	0x0001
#define CMD_APPEND	0x0002
#define CMD_DELETE	0x0004
#define CMD_FLUSH	0x0008
#define CMD_RESET	0x0010
#define CMD_POLICY	0x0020
#define CMD_CHECK	0x0040
#define CMD_HELP	0x0080
#define CMD_INSERT	0x0100
#define CMD_TIMEOUT	0x0200

#define OPT_NONE	0x000000
#define OPT_EXTENDED	0x000001
#define OPT_NUMERIC	0x000002
#define OPT_SOURCE	0x000004
#define OPT_DESTINATION	0x000008
#define OPT_PROTOCOL	0x000010
#define OPT_VIAADDR	0x000020
#define OPT_POLICY	0x000040
#define OPT_TCPSYN	0x000080
#define OPT_BIDIR	0x000100
#define OPT_VERBOSE	0x000200
#define OPT_PRINTK	0x000400
#define OPT_EXPANDED	0x000800
#define OPT_TCPACK	0x001000
#define OPT_TOS		0x002000
#define OPT_VIANAME	0x004000
#define OPT_REDIRECT	0x008000
#define OPT_MASQUERADE	0x010000

#define FMT_NUMERIC	0x0001
#define FMT_NOCOUNTS	0x0002
#define FMT_KILOMEGA	0x0004
#define FMT_OPTIONS	0x0008
#define FMT_NOTABLE	0x0010
#define FMT_HEADER	0x0020
#define FMT_NOKIND	0x0040
#define FMT_VIA		0x0080
#define FMT_NONEWLINE	0x0100
#define FMT_DELTAS	0x0200
#define FMT_TOS		0x0400

struct masq {
	unsigned long	expires;	/* Expiration timer */
	unsigned short	kind;		/* Which protocol are we talking? */
	struct in_addr	src, dst;	/* Source and destination IP addresses */
	unsigned short	sport, dport;	/* Source and destination ports */
	unsigned short	mport;		/* Masqueraded port */
	__u32		initseq;	/* Add delta from this seq. on */
	short		delta;		/* Delta in sequence numbers */
	short		pdelta;		/* Delta in sequence numbers before last */
};

struct masq_timeout {
	int	tcp_timeout;
	int	tcp_fin_timeout;
	int	udp_timeout;
} timeouts;

char ipfwadm_version[] = "$Id: ipfwadm.c,v 1.6 2002-03-06 01:51:11 gerg Exp $";
char package_version[] = "ipfwadm 2.3.0, 1996/07/30";

int ssocmd_insert[4] =
	{IP_FW_INSERT_FWD, IP_FW_INSERT_IN, IP_FW_INSERT_OUT, IP_ACCT_INSERT};
int ssocmd_append[4] =
	{IP_FW_APPEND_FWD, IP_FW_APPEND_IN, IP_FW_APPEND_OUT, IP_ACCT_APPEND};
int ssocmd_delete[4] =
	{IP_FW_DELETE_FWD, IP_FW_DELETE_IN, IP_FW_DELETE_OUT, IP_ACCT_DELETE};
int ssocmd_check[4] =
	{IP_FW_CHECK_FWD, IP_FW_CHECK_IN, IP_FW_CHECK_OUT, -1};
int ssocmd_policy[4] =
	{IP_FW_POLICY_FWD, IP_FW_POLICY_IN, IP_FW_POLICY_OUT, -1};
int ssocmd_flush[4] =
	{IP_FW_FLUSH_FWD, IP_FW_FLUSH_IN, IP_FW_FLUSH_OUT, IP_ACCT_FLUSH};
int ssocmd_zero[4] =
	{IP_FW_ZERO_FWD, IP_FW_ZERO_IN, IP_FW_ZERO_OUT, IP_ACCT_ZERO};
char *procfiles[5] = {"/proc/net/ip_forward", "/proc/net/ip_input",
	"/proc/net/ip_output", "/proc/net/ip_acct", "/proc/net/ip_masquerade"};

int chain = CHN_NONE;
int command = CMD_NONE;
long options = OPT_NONE;

char *program;

struct ip_fw firewall;

char *sports[IP_FW_MAX_PORTS];
char *dports[IP_FW_MAX_PORTS];
char *rport;
char *shostnetworkmask, *dhostnetworkmask;
int nsaddrs, ndaddrs;
struct in_addr *saddrs, *daddrs;

extern struct in_addr *parse_hostnetwork(char *, int *);
extern void parse_hostnetworkmask(char *, struct in_addr **,
	struct in_addr *, int *);
extern void parse_viahost(char *);
extern struct in_addr *parse_mask(char *);
extern void parse_direction(char *);
extern void parse_policy(char *);
extern void parse_protocol(char *);
extern void parse_all_ports(char **, unsigned short *, int, int);
extern unsigned short parse_port(char *, unsigned short);
extern void store_port(char *, unsigned short *, int, char *[]);
extern void parse_hexbyte(char *, unsigned char *);
extern int parse_timeout(char *);

extern struct in_addr *host_to_addr(char *, int *);
extern char *addr_to_host(struct in_addr *);
extern struct in_addr *network_to_addr(char *);
extern char *addr_to_network(struct in_addr *);
extern char *addr_to_anyname(struct in_addr *);
extern struct in_addr *dotted_to_addr(char *);
extern char *addr_to_dotted(struct in_addr *);
extern char *mask_to_dotted(struct in_addr *);
extern int service_to_port(char *, unsigned short);
extern char *port_to_service(int, unsigned short);
extern long string_to_number(char *, long, long);
extern char *policy_to_string(int);

extern int add_delete_entries(int, int);
extern int check_entries(int);
extern int list_entries(int, char *);
extern int list_masq();

extern void print_firewall(FILE *, struct ip_fw *, int);
extern void print_masq(FILE *, struct masq *, int);
extern int read_procinfo(FILE *, struct ip_fw *, int);
extern int read_masqinfo(FILE *, struct masq *, int);
extern struct ip_fwpkt *fw_to_fwpkt(struct ip_fw *);
extern int do_setsockopt(int, void *, int);

extern void check_option(long, char);
extern void inaddrcpy(struct in_addr *, struct in_addr *);
extern void *fw_malloc(size_t);
extern void *fw_calloc(size_t, size_t);
extern void *fw_realloc(void *, size_t);
extern void exit_error(int, char *);
extern void exit_tryhelp(int);
extern void exit_printhelp();

int
main(int argc, char *argv[])
{
	int c, kind, ret = 0, policy, dummy;

	program = argv[0];

	while ((c = getopt(argc, argv, "AFIMOadilzfs:p:chP:S:D:V:W:bekmnort:vxy")) != -1)
		switch (c) {
		case 'A':
			if (chain != CHN_NONE)
				exit_error(2, "multiple categories specified");
			chain = CHN_ACCT;
			if (optind < argc && argv[optind][0] != '-')
				parse_direction(argv[optind++]);
			break;
		case 'F':
			if (chain != CHN_NONE)
				exit_error(2, "multiple categories specified");
			chain = CHN_FWD;
			break;
		case 'I':
			if (chain != CHN_NONE)
				exit_error(2, "multiple categories specified");
			chain = CHN_IN;
			break;
		case 'M':
			if (chain != CHN_NONE)
				exit_error(2, "multiple categories specified");
			chain = CHN_MASQ;
			break;
		case 'O':
			if (chain != CHN_NONE)
				exit_error(2, "multiple categories specified");
			chain = CHN_OUT;
			break;
		case 'a':
			if (command != CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = CMD_APPEND;
			if (optind < argc && argv[optind][0] != '-') {
				parse_policy(argv[optind++]);
				options |= OPT_POLICY;
			}
			break;
		case 'd':
			if (command != CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = CMD_DELETE;
			if (optind < argc && argv[optind][0] != '-') {
				parse_policy(argv[optind++]);
				options |= OPT_POLICY;
			}
			break;
		case 'i':
			if (command != CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = CMD_INSERT;
			if (optind < argc && argv[optind][0] != '-') {
				parse_policy(argv[optind++]);
				options |= OPT_POLICY;
			}
			break;
		case 'l':
			if (command != CMD_NONE && command != CMD_RESET)
				exit_error(2, "multiple commands specified");
			command |= CMD_LIST;
			break;
		case 'z':
			if (command != CMD_NONE && command != CMD_LIST)
				exit_error(2, "multiple commands specified");
			command |= CMD_RESET;
			break;
		case 'f':
			if (command != CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = CMD_FLUSH;
			break;
		case 'p':
			if (command != CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = CMD_POLICY;
			parse_policy(optarg);
			break;
		case 's':
#ifndef	IPFWADM_NO_TIMEOUT
			if (command != CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = CMD_TIMEOUT;
			if (optind + 1 < argc && argv[optind][0] != '-' &&
					argv[optind+1][0] != '-') {
				timeouts.tcp_timeout =
					HZ * parse_timeout(optarg);
				timeouts.tcp_fin_timeout =
					HZ * parse_timeout(argv[optind++]);
				timeouts.udp_timeout =
					HZ * parse_timeout(argv[optind++]);
			} else
				exit_error(2, "-s requires 3 timeout values");
#else	/* IPFWADM_NO_TIMEOUT */
			exit_error(2, "setting masquerading timeouts not supported");
#endif	/* IPFWADM_NO_TIMEOUT */
			break;
		case 'c':
			if (command != CMD_NONE)
				exit_error(2, "multiple commands specified");
			command = CMD_CHECK;
			break;
		case 'h':
			exit_printhelp();
			/* we'll never reach this */
			break;
		case 'P':
			check_option(OPT_PROTOCOL, 'P');
			parse_protocol(optarg);
			break;
		case 'S':
			check_option(OPT_SOURCE, 'S');
			shostnetworkmask = optarg;
			while (optind < argc && argv[optind][0] != '-')
				store_port(argv[optind++], &firewall.fw_nsp,
					IP_FW_F_SRNG, sports);
			break;
		case 'D':
			check_option(OPT_DESTINATION, 'D');
			dhostnetworkmask = optarg;
			while (optind < argc && argv[optind][0] != '-')
				store_port(argv[optind++], &firewall.fw_ndp,
					IP_FW_F_DRNG, dports);
			break;
		case 'V':
			check_option(OPT_VIAADDR, 'V');
			parse_viahost(optarg);
			break;
		case 'W':
			check_option(OPT_VIANAME, 'W');
			strncpy(firewall.fw_vianame, optarg, IFNAMSIZ);
			break;
		case 'b':
			check_option(OPT_BIDIR, 'b');
			firewall.fw_flg |= IP_FW_F_BIDIR;
			break;
		case 'e':
			check_option(OPT_EXTENDED, 'e');
			break;
		case 'k':
			check_option(OPT_TCPACK, 'k');
			firewall.fw_flg |= IP_FW_F_TCPACK;
			break;
		case 'm':
			check_option(OPT_MASQUERADE, 'm');
			firewall.fw_flg |= IP_FW_F_MASQ;
			break;
		case 'n':
			check_option(OPT_NUMERIC, 'n');
			break;
		case 'o':
			check_option(OPT_PRINTK, 'o');
			firewall.fw_flg |= IP_FW_F_PRN;
			break;
		case 'r':
#ifndef	IPFWADM_NO_REDIR
			check_option(OPT_REDIRECT, 'r');
			firewall.fw_flg |= IP_FW_F_REDIR;
			if (optind < argc && argv[optind][0] != '-')
				rport = argv[optind++];
			else
				rport = "0";
#else	/* IPFWADM_NO_REDIR */
			exit_error(2, "redirection not supported");
#endif	/* IPFWADM_NO_REDIR */
			break;
		case 't':
			check_option(OPT_TOS, 't');
			if (optind < argc && argv[optind][0] != '-') {
				parse_hexbyte(optarg, &firewall.fw_tosand);
				parse_hexbyte(argv[optind++], &firewall.fw_tosxor);
			} else
				exit_error(2, "-t requires 2 hexbyte arguments");
			break;
		case 'v':
			check_option(OPT_VERBOSE, 'v');
			break;
		case 'x':
			check_option(OPT_EXPANDED, 'x');
			break;
		case 'y':
			check_option(OPT_TCPSYN, 'y');
			firewall.fw_flg |= IP_FW_F_TCPSYN;
			break;
		case '?':
		default:
			exit_tryhelp(2);
		}

	if (optind < argc)
		exit_error(2, "unknown arguments found on commandline");
	else if (!command)
		exit_error(2, "no command specified");

	kind = firewall.fw_flg & IP_FW_F_KIND;
	policy = (int) (firewall.fw_flg &
		(IP_FW_F_ACCEPT | IP_FW_F_ICMPRPL | IP_FW_F_MASQ));

	if (chain == CHN_NONE)
		exit_error(2, "missing -A, -F, -I, -O, or -M flag");
	else if (chain != CHN_IN && chain != CHN_OUT && chain != CHN_FWD &&
			command == CMD_CHECK)
		exit_error(2, "specify either -F, -I, or -O for checking a packet");
	else if (chain != CHN_IN && chain != CHN_OUT && chain != CHN_FWD &&
			command == CMD_POLICY)
		exit_error(2, "specify either -F, -I, or -O for changing the policy");
	else if ((chain == CHN_IN || chain == CHN_OUT || chain == CHN_FWD) &&
			!(options & OPT_POLICY) &&
			(command & (CMD_INSERT | CMD_APPEND | CMD_DELETE)))
		exit_error(2, "policy required for firewall entries");
	else if (chain != CHN_IN && chain != CHN_OUT && chain != CHN_FWD &&
			options & OPT_POLICY)
		/* command is CMD_INSERT, CMD_APPEND, or CMD_DELETE */
		exit_error(2, "no policy allowed with non-firewall entries");
	else if (chain == CHN_MASQ && !(command & CMD_TIMEOUT) && !(command & CMD_LIST))
		exit_error(2, "-M only allowed in combination with -s or -l command");
	else if (chain != CHN_MASQ && command & CMD_TIMEOUT)
		exit_error(2, "setting masquerading timeouts requires -M flag");

	if ((options & OPT_BIDIR) &&
			!(command & (CMD_INSERT | CMD_APPEND | CMD_DELETE)))
		exit_error(2, "bidirectional flag (-b) only allowed with insert/append/delete");
	else if ((options & OPT_PRINTK) &&
			!(command & (CMD_INSERT | CMD_APPEND | CMD_DELETE)))
		exit_error(2, "kernel print flag (-o) only allowed with insert/append/delete");
	else if ((options & OPT_REDIRECT) &&
			!(command & (CMD_INSERT | CMD_APPEND | CMD_DELETE)))
		exit_error(2, "port redirection (-r) only allowed with insert/append/delete");
	else if ((options & OPT_TOS) &&
			!(command & (CMD_INSERT | CMD_APPEND | CMD_DELETE)))
		exit_error(2, "tos values (-t) only allowed with insert/append/delete");

	if ((options & OPT_PROTOCOL) && (command & (CMD_LIST | CMD_FLUSH |
			CMD_RESET | CMD_POLICY)))
		exit_error(2, "no protocol (-P) allowed with this command");
	else if (!(options & OPT_PROTOCOL) && command == CMD_CHECK)
		exit_error(2, "protocol (-P) required for this command");
	else if (!(options & OPT_PROTOCOL))
		firewall.fw_flg |= IP_FW_F_ALL;

	if (command == CMD_CHECK && kind == IP_FW_F_ALL)
		exit_error(2, "specific protocol required for check command");

	if ((options & OPT_VIAADDR) && (command & (CMD_LIST | CMD_FLUSH |
			CMD_RESET | CMD_POLICY)))
		exit_error(2, "no interface address (-V) allowed with this command");
	if (!(options & OPT_VIAADDR) && (command & CMD_CHECK))
		exit_error(2, "interface address (-V) required for this command");

	if ((options & OPT_VIANAME) && (command & (CMD_LIST | CMD_FLUSH |
			CMD_RESET | CMD_POLICY)))
		exit_error(2, "no interface name (-W) allowed with this command");
	if (!(options & OPT_VIANAME) && (command & CMD_CHECK))
		exit_error(2, "interface name (-W) required for this command");

	if (kind == IP_FW_F_ICMP && firewall.fw_ndp != 0)
		exit_error(2, "ICMP types only allowed with -S, not with -D");
	else if (kind == IP_FW_F_ALL && (firewall.fw_nsp != 0 || firewall.fw_ndp != 0))
		exit_error(2, "no ports allowed without specific protocol");
	else if (command == CMD_CHECK && kind != IP_FW_F_ICMP &&
			(firewall.fw_nsp != 1 || firewall.fw_ndp != 1))
		exit_error(2, "one port required with source/destination address");
	else if (command == CMD_CHECK && kind == IP_FW_F_ICMP &&
			(firewall.fw_nsp != 1 || firewall.fw_ndp != 0))
		exit_error(2, "ICMP type required after source address");
	else if (options & OPT_REDIRECT && chain != CHN_IN)
		exit_error(2, "redirecting only allowed in combination with -I");
	else if (kind == IP_FW_F_ICMP && options & OPT_REDIRECT)
		exit_error(2, "redirecting not allowed with protocol ICMP");
	else if (options & OPT_MASQUERADE && chain != CHN_FWD)
		exit_error(2, "masquerading only allowed in combination with -F");
	else if (kind == IP_FW_F_ICMP && options & OPT_MASQUERADE)
		exit_error(2, "masquerading not allowed with protocol ICMP");
	else if (options & OPT_MASQUERADE && !(policy & IP_FW_F_ACCEPT))
		exit_error(2, "masquerading only allowed with policy accept");

	if ((options & OPT_SOURCE) && (command & (CMD_LIST | CMD_FLUSH |
			CMD_RESET | CMD_POLICY)))
		exit_error(2, "no source address (-S) allowed with this command");
	else if (!(options & OPT_SOURCE) && (command & CMD_CHECK))
		exit_error(2, "source address (-S) required for this command");
	else if (!(options & OPT_SOURCE) && (command &
			(CMD_INSERT | CMD_APPEND | CMD_DELETE)))
		shostnetworkmask = "0.0.0.0/0";
	if (shostnetworkmask) {
		parse_hostnetworkmask(shostnetworkmask, &saddrs,
			&(firewall.fw_smsk), &nsaddrs);
		parse_all_ports(sports, &(firewall.fw_pts[0]),
			(int) firewall.fw_nsp, firewall.fw_flg & IP_FW_F_SRNG);
	}

	if ((options & OPT_DESTINATION) && (command & (CMD_LIST | CMD_FLUSH |
			CMD_RESET | CMD_POLICY)))
		exit_error(2, "no destination address (-D) allowed with this command");
	else if (!(options & OPT_DESTINATION) && (command & CMD_CHECK))
		exit_error(2, "destination address (-D) required for this command");
	else if (!(options & OPT_DESTINATION) && (command &
			(CMD_INSERT | CMD_APPEND | CMD_DELETE)))
		dhostnetworkmask = "0.0.0.0/0";
	if (dhostnetworkmask) {
		parse_hostnetworkmask(dhostnetworkmask, &daddrs,
			&(firewall.fw_dmsk), &ndaddrs);
		parse_all_ports(dports, &(firewall.fw_pts[firewall.fw_nsp]),
			(int) firewall.fw_ndp, firewall.fw_flg & IP_FW_F_DRNG);
	}

	if (options & OPT_REDIRECT) {
		if (firewall.fw_nsp + firewall.fw_ndp >= IP_FW_MAX_PORTS) {
			fprintf(stderr, "%s: too many ports specified (maximum %d when using -r option)\n",
				program, IP_FW_MAX_PORTS - 1);
			exit_tryhelp(2);
		}
		firewall.fw_pts[firewall.fw_nsp + firewall.fw_ndp] =
			parse_port(rport, kind);
	}

	if (!(options & OPT_TOS)) {
		firewall.fw_tosand = 0xFF;
		firewall.fw_tosxor = 0x00;
	}

	switch (command) {
	case CMD_INSERT:
		ret = add_delete_entries(ssocmd_insert[chain], chain);
		break;
	case CMD_APPEND:
		ret = add_delete_entries(ssocmd_append[chain], chain);
		break;
	case CMD_DELETE:
		ret = add_delete_entries(ssocmd_delete[chain], chain);
		break;
	case CMD_CHECK:
		ret = check_entries(ssocmd_check[chain]);
		break;
	case CMD_POLICY:
		ret = do_setsockopt(ssocmd_policy[chain], &policy, sizeof(int));
		break;
	case CMD_FLUSH:
		ret = do_setsockopt(ssocmd_flush[chain], &dummy, sizeof(dummy));
		break;
	case CMD_RESET:
		ret = do_setsockopt(ssocmd_zero[chain], &dummy, sizeof(dummy));
		break;
	case CMD_TIMEOUT:
		ret = do_setsockopt(IP_FW_MASQ_TIMEOUTS, &timeouts, sizeof(timeouts));
		break;
	case CMD_LIST:
	case CMD_LIST | CMD_RESET:
		if (chain == CHN_MASQ)
			ret = list_masq();
		else
			ret = list_entries(chain, (command & CMD_RESET) ? "r+" : "r");
		break;
	default:
		/* We should never reach this... */
		exit_tryhelp(2);
	}
	exit(ret);
}

/*
 *	All functions starting with "parse" should succeed, otherwise
 *	the program fails.  These routines will modify the global
 *	ip_fw stucture "firewall" and/or they modify one of the other
 *	global variables used to save the specified parameters.
 *
 *	Most routines return pointers to static data that may change
 *	between calls to the same or other routines with a few exceptions:
 *	"host_to_addr", "parse_hostnetwork", and "parse_hostnetworkmask"
 *	return global static data.
*/

struct in_addr *
parse_hostnetwork(char *name, int *naddrs)
{
	struct in_addr *addrp, *addrptmp;

	if ((addrptmp = dotted_to_addr(name)) != NULL) {
		addrp = fw_malloc(sizeof(struct in_addr));
		inaddrcpy(addrp, addrptmp);
		*naddrs = 1;
		return addrp;
	} else if ((addrptmp = network_to_addr(name)) != NULL) {
		addrp = fw_malloc(sizeof(struct in_addr));
		inaddrcpy(addrp, addrptmp);
		*naddrs = 1;
		return addrp;
	} else if ((addrp = host_to_addr(name, naddrs)) != NULL) {
		return addrp;
	} else {
		fprintf(stderr, "%s: host/network \"%s\" not found\n",
			program, name);
		exit_tryhelp(2);
		/* make the compiler happy... */
		return NULL;
	}
}

void
parse_hostnetworkmask(char *name, struct in_addr **addrpp,
		struct in_addr *maskp, int *naddrs)
{
	struct in_addr *addrp;
	char buf[256];
	char *p;
	int i, j, k, n;

	strncpy(buf, name, sizeof(buf) - 1);
	if ((p = strrchr(buf, '/')) != NULL) {
		*p = '\0';
		addrp = parse_mask(p + 1);
	} else
		addrp = parse_mask(NULL);
	inaddrcpy(maskp, addrp);

	/* if a null mask is given, the name is ignored, like in "any/0" */
	if (maskp->s_addr == 0L)
		strcpy(buf, "0.0.0.0");

	addrp = *addrpp = parse_hostnetwork(buf, naddrs);
	n = *naddrs;
	for (i = 0, j = 0; i < n; i++) {
		addrp[j++].s_addr &= maskp->s_addr;
		for (k = 0; k < j - 1; k++) {
			if (addrp[k].s_addr == addrp[j - 1].s_addr) {
				(*naddrs)--;
				j--;
				break;
			}
		}
	}
}

void
parse_viahost(char *name)
{
	struct in_addr *addrp;
	int naddrs;

	if ((addrp = dotted_to_addr(name)) != NULL) {
		inaddrcpy(&firewall.fw_via, addrp);
		return;
	} else if ((addrp = host_to_addr(name, &naddrs)) != NULL) {
		if (naddrs != 1) {
			fprintf(stderr,
				"%s: hostname \"%s\" does not specify a unique address\n",
				program, name);
			exit_tryhelp(2);
		} else {
			inaddrcpy(&firewall.fw_via, addrp);
			return;
		}
	} else {
		fprintf(stderr, "%s: host \"%s\" not found\n", program, name);
		exit_tryhelp(2);
	}
}

struct in_addr *
parse_mask(char *mask)
{
	static struct in_addr maskaddr;
	struct in_addr *addrp;
	int bits;

	if (mask == NULL) {
		/* no mask at all defaults to 32 bits */
		maskaddr.s_addr = 0xFFFFFFFF;
		return &maskaddr;
	} else if ((addrp = dotted_to_addr(mask)) != NULL) {
		/* dotted_to_addr already returns a network byte order addr */
		return addrp;
	} else if ((bits = string_to_number(mask, 0, 32)) == -1) {
		fprintf(stderr, "%s: invalid mask \"%s\" specified\n", program, mask);
		exit_tryhelp(2);
		/* make the compiler happy... */
		return NULL;
	} else if (bits != 0) {
		maskaddr.s_addr = htonl(0xFFFFFFFF << (32 - bits));
		return &maskaddr;
	} else {
		maskaddr.s_addr = 0L;
		return &maskaddr;
	}
}

void
parse_direction(char *s)
{
	unsigned short direction;

	if (strncmp("in", s, strlen(s)) == 0)
#ifndef	IPFWADM_NO_ACCTDIR
		direction = IP_FW_F_ACCTIN;
#else	/* IPFWADM_NO_ACCTDIR */
		exit_error(2, "accounting direction \"in\" not supported");
#endif	/* IPFWADM_NO_ACCTDIR */
	else if (strncmp("out", s, strlen(s)) == 0)
#ifndef	IPFWADM_NO_ACCTDIR
		direction = IP_FW_F_ACCTOUT;
#else	/* IPFWADM_NO_ACCTDIR */
		exit_error(2, "accounting direction \"out\" not supported");
#endif	/* IPFWADM_NO_ACCTDIR */
	else if (strncmp("both", s, strlen(s)) == 0)
		direction = 0;
	else {
		fprintf(stderr, "%s: invalid direction \"%s\" specified\n", program, s);
		exit_tryhelp(2);
		/* make the compiler happy... */
		return;
	}
	firewall.fw_flg |= direction;
	return;
}

void
parse_policy(char *s)
{
	unsigned short policy;

	if (strncmp("accept", s, strlen(s)) == 0)
		policy = IP_FW_F_ACCEPT;
	else if (strncmp("deny", s, strlen(s)) == 0)
		policy = 0; /* as opposed to IP_FW_F_ACCEPT */
	else if (strncmp("reject", s, strlen(s)) == 0)
		policy = IP_FW_F_ICMPRPL;
	else if (strncmp("masquerade", s, strlen(s)) == 0) {
		/* for backwards compatibility, better use "accept" and "-m" */
		check_option(OPT_MASQUERADE, 'm');
		policy = IP_FW_F_ACCEPT | IP_FW_F_MASQ;
	} else {
		fprintf(stderr, "%s: invalid policy \"%s\" specified\n", program, s);
		exit_tryhelp(2);
		/* make the compiler happy... */
		return;
	}
	firewall.fw_flg |= policy;
	return;
}

void
parse_protocol(char *s)
{
	unsigned short protocol;

	if (strncmp("all", s, strlen(s)) == 0)
		protocol = IP_FW_F_ALL;
	else if (strncmp("tcp", s, strlen(s)) == 0)
		protocol = IP_FW_F_TCP;
	else if (strncmp("udp", s, strlen(s)) == 0)
		protocol = IP_FW_F_UDP;
	else if (strncmp("icmp", s, strlen(s)) == 0)
		protocol = IP_FW_F_ICMP;
	else {
		fprintf(stderr, "%s: invalid protocol \"%s\" specified\n", program, s);
		exit_tryhelp(2);
		/* make the compiler happy... */
		return;
	}
	firewall.fw_flg |= protocol;
}

void
parse_all_ports(char **ports, unsigned short *portnumbers,
		int nports, int range)
{
	int i, j;
	unsigned short kind;
	char buf[256], *cp;

	kind = firewall.fw_flg & IP_FW_F_KIND;

	for (i = 0, j = (range ? 2 : 0); i < nports; i++) {
		if (ports[i] == NULL)
			continue;
		strncpy(buf, ports[i], sizeof(buf) - 1);
		if ((cp = strchr(buf, (int) ':')) == NULL)
			portnumbers[j++] = parse_port(buf, kind);
		else {
			*cp = '\0';
			portnumbers[0] = parse_port(buf, kind);
			portnumbers[1] = parse_port(cp + 1, kind);
			if (portnumbers[0] > portnumbers[1]) {
				fprintf(stderr, "%s: invalid range of ports (%u > %u)\n",
					program, portnumbers[0], portnumbers[1]);
				exit_tryhelp(2);
			}
		}
	}
}

unsigned short
parse_port(char *port, unsigned short kind)
{
	int portnum;

	if ((portnum = string_to_number(port, 0, 65535)) != -1)
		return (unsigned short) portnum;
	else if (kind == IP_FW_F_ICMP) {
		/* ICMP types (given as port numbers) must be numeric! */
		fprintf(stderr, "%s: invalid ICMP type \"%s\" specified\n",
			program, port);
		exit_tryhelp(2);
		/* make the compiler happy... */
		return 0;
	} else if ((portnum = service_to_port(port, kind)) != -1)
		return (unsigned short) portnum;
	else {
		fprintf(stderr, "%s: invalid port/service \"%s\" specified\n",
			program, port);
		exit_tryhelp(2);
		/* make the compiler happy... */
		return 0;
	}
}

void
store_port(char *port, unsigned short *nports, int rangeflag, char *ports[])
{
	/* to count the # ports, check whether this is a range or not */
	if (strchr(port, (int) ':') == NULL)
		*nports += 1;
	else if (firewall.fw_flg & rangeflag)
		exit_error(2, "multiple ranges not allowed");
	else {
		*nports += 2;
		firewall.fw_flg |= rangeflag;
	}

	if (firewall.fw_nsp + firewall.fw_ndp > IP_FW_MAX_PORTS) {
		fprintf(stderr, "%s: too many ports specified (maximum %d)\n",
			program, IP_FW_MAX_PORTS);
		exit_tryhelp(2);
	}
	ports[*nports - 1] = port;
	return;
}

void
parse_hexbyte(char *s, unsigned char *b)
{
	long number;
	char *end;

	number = strtol(s, &end, 16);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (0 <= number && number <= 255)
			*b = (unsigned char) number;
		else {
			fprintf(stderr, "%s: invalid hexbyte \"%s\" specified\n",
				program, s);
			exit_tryhelp(2);
		}
	} else {
		fprintf(stderr, "%s: invalid hexbyte \"%s\" specified\n",
			program, s);
		exit_tryhelp(2);
	}
}

int
parse_timeout(char *s)
{
	int timeout;

	if ((timeout = string_to_number(s, 0, INT_MAX)) != -1)
		return timeout;
	else {
		fprintf(stderr, "%s: invalid timeout value \"%s\" specified\n",
			program, s);
		exit_tryhelp(2);
		/* make the compiler happy... */
		return 0;
	}
}

struct in_addr *
host_to_addr(char *name, int *naddr)
{
	struct hostent *host;
	struct in_addr *addr;
	int i;

	*naddr = 0;
	if ((host = gethostbyname(name)) != NULL) {
		if (host->h_addrtype != AF_INET ||
				host->h_length != sizeof(struct in_addr))
			return (struct in_addr *) NULL;
		while (host->h_addr_list[*naddr] != (char *) NULL)
			(*naddr)++;
		addr = fw_calloc(*naddr, sizeof(struct in_addr));
		for (i = 0; i < *naddr; i++)
			inaddrcpy(&(addr[i]), (struct in_addr *) host->h_addr_list[i]);
		return addr;
	} else
		return (struct in_addr *) NULL;
}

char *
addr_to_host(struct in_addr *addr)
{
	struct hostent *host;

	if ((host = gethostbyaddr((char *) addr,
			sizeof(struct in_addr), AF_INET)) != NULL)
		return (char *) host->h_name;
	else
		return (char *) NULL;
}

struct in_addr *
network_to_addr(char *name)
{
	struct netent *net;
	static struct in_addr addr;

#ifndef EMBED
	if ((net = getnetbyname(name)) != NULL) {
		if (net->n_addrtype != AF_INET)
			return (struct in_addr *) NULL;
		addr.s_addr = htonl((unsigned long) net->n_net);
		return &addr;
	} else
#endif
		return (struct in_addr *) NULL;
}

char *
addr_to_network(struct in_addr *addr)
{
	struct netent *net;
 
#ifndef EMBED
	if ((net = getnetbyaddr((long) ntohl(addr->s_addr), AF_INET)) != NULL)
		return (char *) net->n_name;
	else
#endif
		return (char *) NULL;
}

char *
addr_to_anyname(struct in_addr *addr)
{
	char *name;

	if ((name = addr_to_host(addr)) != NULL)
		return name;
	else if ((name = addr_to_network(addr)) != NULL)
		return name;
	else
		return addr_to_dotted(addr);
}

struct in_addr *
dotted_to_addr(char *dotted)
{
	static struct in_addr addr;
	unsigned char *addrp;
	char *p, *q;
	int onebyte, i;
	char buf[20];

	/* copy dotted string, because we need to modify it */
	strncpy(buf, dotted, sizeof(buf) - 1);
	addrp = (unsigned char *) &(addr.s_addr);

	p = buf;
	for (i = 0; i < 3; i++) {
		if ((q = strchr(p, '.')) == NULL)
			return (struct in_addr *) NULL;
		else {
			*q = '\0';
			if ((onebyte = string_to_number(p, 0, 255)) == -1)
				return (struct in_addr *) NULL;
			else
				addrp[i] = (unsigned char) onebyte;
		}
		p = q + 1;
	}

	/* we've checked 3 bytes, now we check the last one */
	if ((onebyte = string_to_number(p, 0, 255)) == -1)
		return (struct in_addr *) NULL;
	else
		addrp[3] = (unsigned char) onebyte;
		
	return &addr;
}

char *
addr_to_dotted(struct in_addr *addrp)
{
	static char buf[20];
	unsigned char *bytep;

	bytep = (unsigned char *) &(addrp->s_addr);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}

char *
mask_to_dotted(struct in_addr *mask)
{
	int i;
	static char buf[20];
	__u32 maskaddr, bits;

	maskaddr = ntohl(mask->s_addr);

	if (maskaddr == 0xFFFFFFFFL)
		/* we don't want to see "/32" */
		return "";
	else {
		i = 32;
		bits = 0xFFFFFFFEL;
		while (--i >= 0 && maskaddr != bits)
			bits <<= 1;
		if (i >= 0)
			sprintf(buf, "/%d", i);
		else
			/* mask was not a decent combination of 1's and 0's */
			sprintf(buf, "/%s", addr_to_dotted(mask));
		return buf;
	}
}

int
service_to_port(char *name, unsigned short kind)
{
	struct servent *service;

	if (kind == IP_FW_F_TCP && (service = getservbyname(name, "tcp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else if (kind == IP_FW_F_UDP &&
			(service = getservbyname(name, "udp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else
		return -1;
}

char *
port_to_service(int port, unsigned short kind)
{
	struct servent *service;

	if (kind == IP_FW_F_TCP &&
			(service = getservbyport(htons(port), "tcp")) != NULL)
		return service->s_name;
	else if (kind == IP_FW_F_UDP &&
			(service = getservbyport(htons(port), "udp")) != NULL)
		return service->s_name;
	else
		return (char *) NULL;
}

long
string_to_number(char *s, long min, long max)
{
	long number;
	char *end;

	number = strtol(s, &end, 10);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (min <= number && number <= max)
			return number;
		else
			return -1;
	} else
		return -1;
}

char *
policy_to_string(int policy)
{
	switch (policy) {
	case IP_FW_F_ACCEPT:
		return "accept";
	case IP_FW_F_ACCEPT | IP_FW_F_MASQ:
		return "accept/masquerade";
	case IP_FW_F_ICMPRPL:
		return "reject";
	default:
		return "deny";
	}
}

int
add_delete_entries(int cmd, int chain)
{
	int ret = 0, i, j;

	for (i = 0; i < nsaddrs; i++) {
		firewall.fw_src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			firewall.fw_dst.s_addr = daddrs[j].s_addr;
			if (options & OPT_VERBOSE)
				print_firewall(stdout, &firewall, FMT_NOCOUNTS | FMT_OPTIONS |
					FMT_TOS | FMT_VIA | FMT_NUMERIC | FMT_NOTABLE);
			ret |= do_setsockopt(cmd, &firewall, sizeof(firewall));
		}
	}
	return ret;
}

int
check_entries(int cmd)
{
	int ret = 0, i, j;
	struct ip_fwpkt *packet;

	for (i = 0; i < nsaddrs; i++) {
		firewall.fw_src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			firewall.fw_dst.s_addr = daddrs[j].s_addr;
			if (options & OPT_VERBOSE)
				print_firewall(stdout, &firewall, FMT_NOCOUNTS | FMT_NOKIND |
					FMT_VIA | FMT_NUMERIC | FMT_NOTABLE);
			packet = fw_to_fwpkt(&firewall);
			ret |= do_setsockopt(cmd, packet, sizeof(struct ip_fwpkt));
		}
	}
	return ret;
}

int
list_entries(int chain, char *mode)
{
	FILE *fp;
	char *procfile;
	int policy, i;
	char buf[256];
	struct ip_fw *fwlist;
	int ntotal = 0, nread, format;

	procfile = procfiles[chain];

	if ((fp = fopen(procfile, mode)) == NULL) {
		fprintf(stderr, "%s: cannot open file %s\n", program, procfile);
		exit(1);
	}

	if (chain == CHN_IN || chain == CHN_OUT || chain == CHN_FWD) {
		if (fscanf(fp, "%[^,], default %d", buf, &policy) != 2) {
			fprintf(stderr, "%s: unexpected input from %s\n",
				program, procfile);
			exit(2);
		}
		fprintf(stdout, "%s, default policy: %s\n", buf,
			policy_to_string(policy));
	} else
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			fprintf(stderr, "%s: unexpected input from %s\n",
				program, procfile);
			exit(2);
		} else
			fputs(buf, stdout);

	fwlist = (struct ip_fw *) fw_malloc(16 * sizeof(struct ip_fw));
	while ((nread = read_procinfo(fp, &(fwlist[ntotal]), 16)) == 16) {
		ntotal += nread;
		fwlist = (struct ip_fw *) fw_realloc(fwlist,
			(ntotal + 16) * sizeof(struct ip_fw));
	}
	ntotal += nread;

	format = 0;
	if (chain == CHN_IN || chain == CHN_OUT || chain == CHN_FWD)
		if (!(options & OPT_EXTENDED))
			format |= FMT_NOCOUNTS;

	if (options & OPT_NUMERIC)
		format |= FMT_NUMERIC;

	if (options & OPT_EXTENDED && chain != CHN_ACCT)
		format |= FMT_OPTIONS | FMT_TOS | FMT_VIA;
	else if (options & OPT_EXTENDED)
		format |= FMT_OPTIONS | FMT_VIA;

	if (!(options & OPT_EXPANDED))
		format |= FMT_KILOMEGA;

	if (ntotal > 0)
		for (i = 0; i < ntotal; i++)
			print_firewall(stdout, &(fwlist[i]),
				(i) ? format : (format | FMT_HEADER));

	return 0;
}

int
list_masq()
{
	FILE *fp;
	char *procfile;
	int i;
	char buf[256];
	struct masq *mslist;
	int ntotal = 0, nread, format;

	procfile = procfiles[CHN_MASQ];

	if ((fp = fopen(procfile, "r")) == NULL) {
		fprintf(stderr, "%s: cannot open file %s\n", program, procfile);
		exit(1);
	}

	if (fgets(buf, sizeof(buf), fp) == NULL) {
		fprintf(stderr, "%s: unexpected input from %s\n",
			program, procfile);
		exit(2);
	}

	fputs("IP masquerading entries\n", stdout);

	mslist = (struct masq *) fw_malloc(16 * sizeof(struct masq));
	while ((nread = read_masqinfo(fp, &(mslist[ntotal]), 16)) == 16) {
		ntotal += nread;
		mslist = (struct masq *) fw_realloc(mslist,
			(ntotal + 16) * sizeof(struct masq));
	}
	ntotal += nread;

	format = 0;

	if (options & OPT_NUMERIC)
		format |= FMT_NUMERIC;

	if (options & OPT_EXTENDED)
		format |= FMT_DELTAS;

	if (ntotal > 0)
		for (i = 0; i < ntotal; i++)
			print_masq(stdout, &(mslist[i]),
				(i) ? format : (format | FMT_HEADER));

	return 0;
}

void
print_firewall(FILE *fp, struct ip_fw *fw, int format)
{
	unsigned short flags, kind;
	unsigned long cnt, cntkb, cntmb;
	char buf[BUFSIZ];
	char *service;
	int i;

	flags = fw->fw_flg;
	kind = flags & IP_FW_F_KIND;

#define FMT(tab,notab) ((format & FMT_NOTABLE) ? notab : tab)

	if (format & FMT_HEADER) {
		if (!(format & FMT_NOCOUNTS)) {
			if (format & FMT_KILOMEGA) {
				fprintf(fp, FMT("%5s ","%s "), "pkts");
				fprintf(fp, FMT("%5s ","%s "), "bytes");
			} else {
				fprintf(fp, FMT("%8s ","%s "), "pkts");
				fprintf(fp, FMT("%10s ","%s "), "bytes");
			}
		}
		if (!(format & FMT_NOKIND)) {
			if (chain == CHN_ACCT)
				fprintf(fp, FMT("%-3s ","%s "), "dir");
			else
				fprintf(fp, FMT("%-5s ","%s "), "type");
		}
		fputs("prot ", fp);
		if (format & FMT_OPTIONS)
			fputs("opt  ", fp);
		if (format & FMT_TOS)
			fputs("tosa tosx ", fp);
		if (format & FMT_VIA) {
			fprintf(fp, FMT("%-7s ","(%s "), "ifname");
			fprintf(fp, FMT("%-15s ","%s) "), "ifaddress");
		}
		fprintf(fp, FMT("%-20s ","%s "), "source");
		fprintf(fp, FMT("%-20s ","%s "), "destination");
		fputs("ports\n", fp);
	}

	if (!(format & FMT_NOCOUNTS)) {
		cnt = fw->fw_pcnt;
		if (format & FMT_KILOMEGA) {
			if (cnt > 99999) {
				cntkb = (cnt + 500) / 1000;
				if (cntkb > 9999) {
					cntmb = (cnt + 500000) / 1000000;
					fprintf(fp, FMT("%4luM ","%luM "), cntmb);
				} else
					fprintf(fp, FMT("%4luK ","%luK "), cntkb);
			} else
				fprintf(fp, FMT("%5lu ","%lu "), cnt);
		} else
			fprintf(fp, FMT("%8lu ","%lu "), cnt);
		cnt = fw->fw_bcnt;
		if (format & FMT_KILOMEGA) {
			if (cnt > 99999) {
				cntkb = (cnt + 500) / 1000;
				if (cntkb > 9999) {
					cntmb = (cnt + 500000) / 1000000;
					fprintf(fp, FMT("%4luM ","%luM "), cntmb);
				} else
					fprintf(fp, FMT("%4luK ","%luK "), cntkb);
			} else
				fprintf(fp, FMT("%5lu ","%lu "), cnt);
		} else
			fprintf(fp, FMT("%10lu ","%lu "), cnt);
	}

	if (!(format & FMT_NOKIND)) {
		if (chain == CHN_ACCT) {
			if (flags & IP_FW_F_ACCTIN)
				fprintf(fp, FMT("%-3s ", "%s "), "in");
			else if (flags & IP_FW_F_ACCTOUT)
				fprintf(fp, FMT("%-3s ", "%s "), "out");
			else
				fprintf(fp, FMT("%-3s ", "%s "), "i/o");
		} else {
			if (flags & IP_FW_F_REDIR)
				fprintf(fp, FMT("%-5s ", "%s "), "acc/r");
			else if (flags & IP_FW_F_MASQ)
				fprintf(fp, FMT("%-5s ", "%s "), "acc/m");
			else if (flags & IP_FW_F_ACCEPT)
				fprintf(fp, FMT("%-5s ", "%s "), "acc");
			else if (flags & IP_FW_F_ICMPRPL)
				fprintf(fp, FMT("%-5s ", "%s "), "rej");
			else
				fprintf(fp, FMT("%-5s ", "%s "), "deny");
		}
	}

	switch (kind) {
	case IP_FW_F_TCP:
		fprintf(fp, FMT("%-5s", "%s "), "tcp");
		break;
	case IP_FW_F_UDP:
		fprintf(fp, FMT("%-5s", "%s "), "udp");
		break;
	case IP_FW_F_ICMP:
		fprintf(fp, FMT("%-5s", "%s "), "icmp");
		break;
	default:
		fprintf(fp, FMT("%-5s", "%s "), "all");
	}

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt ", fp);
		fputc((flags & IP_FW_F_BIDIR) ? 'b' : '-', fp);
		fputc((flags & IP_FW_F_TCPACK) ? 'k' : '-', fp);
		fputc((flags & IP_FW_F_TCPSYN) ? 'y' : '-', fp);
		fputc((flags & IP_FW_F_PRN) ? 'o' : '-', fp);
		fputc(' ', fp);
	}

	if (format & FMT_TOS) {
		if (format & FMT_NOTABLE)
			fputs("tos ", fp);
		fprintf(fp, "0x%02hX 0x%02hX ",
			(unsigned short) fw->fw_tosand,
			(unsigned short) fw->fw_tosxor);
	}

	if (format & FMT_VIA) {
		fprintf(fp, FMT("%-7.16s ","via %.16s "),
			(fw->fw_vianame)[0] ? fw->fw_vianame :
				((format & FMT_NUMERIC) ? "*" : "any"));
		fprintf(fp, FMT("%-15s ","%s "), (fw->fw_via.s_addr == 0L &&
			!(format & FMT_NUMERIC)) ? "any" :
			addr_to_dotted(&(fw->fw_via)));
	}

	if (format & FMT_NOTABLE)
		fputs("  ", fp);

	if (fw->fw_smsk.s_addr == 0L && !(format & FMT_NUMERIC))
		fprintf(fp, FMT("%-20s ","%s "), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s", addr_to_dotted(&(fw->fw_src)));
		else
			sprintf(buf, "%s", addr_to_anyname(&(fw->fw_src)));
		strcat(buf, mask_to_dotted(&(fw->fw_smsk)));
		fprintf(fp, FMT("%-20s ","%s "), buf);
	}

	if (fw->fw_dmsk.s_addr == 0L && !(format & FMT_NUMERIC))
		fprintf(fp, FMT("%-20s","-> %s"), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s", addr_to_dotted(&(fw->fw_dst)));
		else
			sprintf(buf, "%s", addr_to_anyname(&(fw->fw_dst)));
		strcat(buf, mask_to_dotted(&(fw->fw_dmsk)));
		fprintf(fp, FMT("%-20s","-> %s"), buf);
	}

	if (format & FMT_NOTABLE)
		fputs("  ", fp);

	if (kind != IP_FW_F_TCP && kind != IP_FW_F_UDP && kind != IP_FW_F_ICMP) {
		fputs(" n/a", fp);
		if (!(format & FMT_NONEWLINE))
			putc('\n', fp);
		return;
	}

	if (fw->fw_nsp == 0)
		fputs((format & FMT_NUMERIC) ? " *" : " any", fp);
	else
		for (i = 0; i < fw->fw_nsp; i++) {
			fputc((i == 0) ? ' ' :
				((flags & IP_FW_F_SRNG && i == 1) ? ':' : ','), fp);
			if (format & FMT_NUMERIC)
				fprintf(fp, "%u", fw->fw_pts[i]);
			else if ((service = port_to_service(fw->fw_pts[i],
					kind)) != NULL)
				fputs(service, fp);
			else
				fprintf(fp, "%u", fw->fw_pts[i]);
		}

	/* only source ports are interpreted as ICMP types */
	if (kind == IP_FW_F_ICMP) {
		if (!(format & FMT_NONEWLINE))
			putc('\n', fp);
		return;
	}

	fputs(" ->", fp);

	if (fw->fw_ndp == 0)
		fputs((format & FMT_NUMERIC) ? " *" : " any", fp);
	else
		for (i = fw->fw_nsp; i < fw->fw_nsp + fw->fw_ndp; i++) {
			fputc((i == fw->fw_nsp) ? ' ' : ((flags & IP_FW_F_DRNG &&
				i == (fw->fw_nsp + 1)) ? ':' : ','), fp);
			if (format & FMT_NUMERIC)
				fprintf(fp, "%u", fw->fw_pts[i]);
			else if ((service = port_to_service(fw->fw_pts[i], kind)) != NULL)
				fputs(service, fp);
			else
				fprintf(fp, "%u", fw->fw_pts[i]);
		}

	if (flags & IP_FW_F_REDIR) {
		i = fw->fw_nsp + fw->fw_ndp;
		if (!fw->fw_pts[i])
			fputs((format & FMT_NUMERIC) ? " => *" : " => any", fp);
		else if (format & FMT_NUMERIC)
			fprintf(fp, " => %u", fw->fw_pts[i]);
		else if ((service = port_to_service(fw->fw_pts[i], kind)) != NULL)
			fprintf(fp, " => %s", service);
		else
			fprintf(fp, " => %u", fw->fw_pts[i]);
	}

	if (!(format & FMT_NONEWLINE))
		putc('\n', fp);
}

void
print_masq(FILE *fp, struct masq *ms, int format)
{
	unsigned long minutes, seconds, sec100s;
	char *service;

	if (format & FMT_HEADER) {
		fputs("prot ", fp);
		fprintf(fp, "%-8s ", "expire");
		if (format & FMT_DELTAS) {
			fprintf(fp, "%10s delta prevd ", "initseq");
		}
		fprintf(fp, "%-20s ", "source");
		fprintf(fp, "%-20s ", "destination");
		fputs("ports\n", fp);
	}

	switch (ms->kind) {
	case IP_FW_F_TCP:
		fprintf(fp, "%-5s", "tcp");
		break;
	case IP_FW_F_UDP:
		fprintf(fp, "%-5s", "udp");
		break;
	}

	sec100s = ms->expires % HZ;
	seconds = (ms->expires / HZ) % 60;
	minutes = ms->expires / (60 * HZ);

	fprintf(fp, "%02ld:%02ld.%02ld ", minutes, seconds, sec100s);

	if (format & FMT_DELTAS) {
		fprintf(fp, "%10lu %5hd %5hd ", (unsigned long) ms->initseq,
			ms->delta, ms->pdelta);
	}

	if (format & FMT_NUMERIC) {
		fprintf(fp, "%-20s ", addr_to_dotted(&(ms->src)));
		fprintf(fp, "%-20s ", addr_to_dotted(&(ms->dst)));
	} else {
		fprintf(fp, "%-20s ", addr_to_anyname(&(ms->src)));
		fprintf(fp, "%-20s ", addr_to_anyname(&(ms->dst)));
	}

	if (format & FMT_NUMERIC)
		fprintf(fp, "%u (%u) -> %u\n", ms->sport, ms->mport, ms->dport);
	else {
		if ((service = port_to_service(ms->sport, ms->kind)) != NULL)
			fprintf(fp, "%s (%u) -> ", service, ms->mport);
		else
			fprintf(fp, "%u (%u) -> ", ms->sport, ms->mport);
		if ((service = port_to_service(ms->dport, ms->kind)) != NULL)
			fprintf(fp, "%s\n", service);
		else
			fprintf(fp, "%u\n", ms->dport);
	}
}

int
read_procinfo(FILE *fp, struct ip_fw *fwlist, int nfwlist)
{
	int i, n, nread = 0;
	struct ip_fw *fw;
	unsigned short tosand, tosxor;
	unsigned long temp[5];

	for (nread = 0; nread < nfwlist; nread++) {
		fw = &fwlist[nread];
		if ((n = fscanf(fp, "%lX/%lX->%lX/%lX %16s %lX %hX %hu %hu %lu %lu",
				&temp[0], &temp[1], &temp[2], &temp[3],
				fw->fw_vianame, &temp[4],
				&fw->fw_flg, &fw->fw_nsp, &fw->fw_ndp,
				&fw->fw_pcnt, &fw->fw_bcnt)) == -1)
			return nread;
		else if (n != 11)
			exit_error(1, "unexpected input data");
		else {
			for (i = 0; i < IP_FW_MAX_PORTS; i++)
				if (fscanf(fp, "%hu", &fw->fw_pts[i]) != 1)
					exit_error(1, "unexpected input data");
			if (fscanf(fp, " A%hX X%hX", &tosand, &tosxor) != 2)
				exit_error(1, "unexpected input data");
			if (!strcmp("-", fw->fw_vianame))
				(fw->fw_vianame)[0] = '\0';
			fw->fw_tosand = (unsigned char) tosand;
			fw->fw_tosxor = (unsigned char) tosxor;
		}

		/* we always keep these addresses in network byte order */
		fw->fw_src.s_addr = (__u32) htonl(temp[0]);
		fw->fw_dst.s_addr = (__u32) htonl(temp[2]);
		fw->fw_via.s_addr = (__u32) htonl(temp[4]);
		fw->fw_smsk.s_addr = (__u32) htonl(temp[1]);
		fw->fw_dmsk.s_addr = (__u32) htonl(temp[3]);
	}
	return nread;
}

int
read_masqinfo(FILE *fp, struct masq *mslist, int nmslist)
{
	int n, nread = 0;
	struct masq *ms;
	char buf[256];
	unsigned long temp[3];

	for (nread = 0; nread < nmslist; nread++) {
		ms = &mslist[nread];
		if ((n = fscanf(fp, " %s %lX:%hX %lX:%hX %hX %lX %hd %hd %lu",
				buf, &temp[0], &ms->sport, &temp[1], &ms->dport,
				&ms->mport, &temp[2], &ms->delta,
				&ms->pdelta, &ms->expires)) == -1)
			return nread;
		else if (n != 10)
			exit_error(1, "unexpected input data");

		if (strcmp("TCP", buf) == 0)
			ms->kind = IP_FW_F_TCP;
		else if (strcmp("UDP", buf) == 0)
			ms->kind = IP_FW_F_UDP;
		else
			exit_error(1, "unexpected input data");

		/* we always keep these addresses in network byte order */
		ms->src.s_addr = (__u32) htonl(temp[0]);
		ms->dst.s_addr = (__u32) htonl(temp[1]);

		ms->initseq = (__u32) temp[2];
	}
	return nread;
}

struct ip_fwpkt *
fw_to_fwpkt(struct ip_fw *fw)
{
	int kind;
	static struct ip_fwpkt ipfwp;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	kind = (fw->fw_flg) & IP_FW_F_KIND;

	iph = &ipfwp.fwp_iph;

	iph->version = IP_VERSION;
	iph->ihl = sizeof(struct iphdr) / 4;
	iph->tot_len = sizeof(struct ip_fwpkt);
	iph->frag_off &= htons(~IP_OFFSET);

	iph->saddr = fw->fw_src.s_addr;
	iph->daddr = fw->fw_dst.s_addr;

	inaddrcpy(&ipfwp.fwp_via, &fw->fw_via);
	strncpy(ipfwp.fwp_vianame, fw->fw_vianame, IFNAMSIZ);

	switch (kind) {
	case IP_FW_F_TCP:
		iph->protocol = IPPROTO_TCP;
		tcph = &ipfwp.fwp_protoh.fwp_tcph;
		tcph->source = htons(fw->fw_pts[0]);
		tcph->dest = htons(fw->fw_pts[1]);
		tcph->syn = (fw->fw_flg & IP_FW_F_TCPSYN) ? 1 : 0;
		break;
	case IP_FW_F_UDP:
		iph->protocol = IPPROTO_UDP;
		udph = &ipfwp.fwp_protoh.fwp_udph;
		udph->source = htons(fw->fw_pts[0]);
		udph->dest = htons(fw->fw_pts[1]);
		break;
	case IP_FW_F_ICMP:
		iph->protocol = IPPROTO_ICMP;
	}

	return &ipfwp;
}

int
do_setsockopt(int cmd, void *data, int length)
{
	static int sockfd = -1;
	int ret;

	if (sockfd == -1) {
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
			perror("ipfwadm: socket creation failed");
			exit(1);
		}
	}
	
	ret = setsockopt(sockfd, IPPROTO_IP, cmd, (char *) data, length);
	if (cmd != IP_FW_CHECK_IN && cmd != IP_FW_CHECK_OUT &&
						cmd != IP_FW_CHECK_FWD) {
		if (ret)
			perror("ipfwadm: setsockopt failed");
	} else {
		if (!ret)
			printf("packet accepted\n");
		else if (errno == ECONNRESET)
			printf("packet masqueraded\n");
		else if (errno == ETIMEDOUT) {
			printf("packet denied\n");
			ret = 0;
		} else if (errno == ECONNREFUSED) {
			printf("packet rejected\n");
			ret = 0;
		} else
			perror("ipfwadm: setsockopt failed");
	}

	return ret;
}

void
check_option(long option, char name)
{
	if (options & option) {
		fprintf(stderr, "%s: multiple -%c flags not allowed\n",
			program, name);
		exit_tryhelp(2);
	}
	options |= option;
}

void
inaddrcpy(struct in_addr *dst, struct in_addr *src)
{
	/* memcpy(dst, src, sizeof(struct in_addr)); */
	dst->s_addr = src->s_addr;
}

void *
fw_malloc(size_t size)
{
	void *p;

	if ((p = malloc(size)) == NULL) {
		perror("ipfwadm: malloc failed");
		exit(1);
	} else
		return p;
}

void *
fw_calloc(size_t count, size_t size)
{
	void *p;

	if ((p = calloc(count, size)) == NULL) {
		perror("ipfwadm: calloc failed");
		exit(1);
	} else
		return p;
}

void *
fw_realloc(void *ptr, size_t size)
{
	void *p;

	if ((p = realloc(ptr, size)) == NULL) {
		perror("ipfwadm: realloc failed");
		exit(1);
	} else
		return p;
}

void
exit_error(int status, char *msg)
{
	fprintf(stderr, "%s: %s\n", program, msg);
	exit_tryhelp(status);
}

void
exit_tryhelp(int status)
{
	fprintf(stderr, "Try `%s -h' for more information.\n", program);
	exit(status);
}

void
exit_printhelp()
{
	printf("%s\n\n"
		"Usage: %s -A [direction] command [options] (accounting)\n"
		"       %s -F command [options] (forwarding firewall)\n"
		"       %s -I command [options] (input firewall)\n"
		"       %s -O command [options] (output firewall)\n"
		"       %s -M [-s | -l] [options] (masquerading entries)\n"
		"       %s -h (print this help information))\n\n",
		package_version, program, program, program, program,
		program, program);

	printf("Commands:\n"
		"  -i [policy]	insert rule (no policy for accounting rules)\n"
		"  -a [policy]	append rule (no policy for accounting rules)\n"
		"  -d [policy]	delete rule (no policy for accounting rules)\n"
		"  -l		list all rules of this category\n"
		"  -z		reset packet/byte counters of all rules of this category\n"
		"  -f		remove all rules of this category\n"
		"  -p policy	change default policy (accept/deny/reject)\n"
		"  -s tcp tcpfin udp\n"
		"		set masuerading timeout values\n"
		"  -c		check acceptance of IP packet\n\n"
		"Options:\n"
		"  -P		protocol (either tcp, udp, icmp, or all)\n"
		"  -S address[/mask] [port ...]\n"
		"		source specification\n"
		"  -D address[/mask] [port ...]\n"
		"		destination specification\n"
		"  -V address	network interface address\n"
		"  -W name	network interface name\n"
		"  -b		bidirectional match\n"
		"  -e		extended output mode\n"
		"  -k		match TCP packets only when ACK set\n"
		"  -m		masquerade packets as coming from local host\n"
		"  -n		numeric output of addresses and ports\n"
		"  -o		turn on kernel logging for matching packets\n"
		"  -r [port]	redirect packets to local port (transparent proxying)\n"
		"  -t and xor	and/xor masks for TOS field\n"
		"  -v		verbose mode\n"
		"  -x		expand numbers (display exact values)\n"
		"  -y		match TCP packets only when SYN set and ACK cleared\n");

	exit(0);
}
