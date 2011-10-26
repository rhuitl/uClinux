%{
/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description: configuration file abstract grammar
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "conntrackd.h"
#include "ignore.h"

extern char *yytext;
extern int   yylineno;

struct ct_conf conf;
%}

%union {
	int		val;
	char		*string;
}

%token T_IPV4_ADDR T_IPV4_IFACE T_PORT T_HASHSIZE T_HASHLIMIT T_MULTICAST
%token T_PATH T_UNIX T_REFRESH T_IPV6_ADDR T_IPV6_IFACE
%token T_IGNORE_UDP T_IGNORE_ICMP T_IGNORE_TRAFFIC T_BACKLOG T_GROUP
%token T_LOG T_UDP T_ICMP T_IGMP T_VRRP T_TCP T_IGNORE_PROTOCOL
%token T_LOCK T_STRIP_NAT T_BUFFER_SIZE_MAX_GROWN T_EXPIRE T_TIMEOUT
%token T_GENERAL T_SYNC T_STATS T_RELAX_TRANSITIONS T_BUFFER_SIZE T_DELAY
%token T_SYNC_MODE T_LISTEN_TO T_FAMILY T_RESEND_BUFFER_SIZE
%token T_PERSISTENT T_NACK T_CHECKSUM T_WINDOWSIZE T_ON T_OFF
%token T_REPLICATE T_FOR T_IFACE 
%token T_ESTABLISHED T_SYN_SENT T_SYN_RECV T_FIN_WAIT 
%token T_CLOSE_WAIT T_LAST_ACK T_TIME_WAIT T_CLOSE T_LISTEN


%token <string> T_IP T_PATH_VAL
%token <val> T_NUMBER
%token <string> T_STRING

%%

configfile :
	   | lines
	   ;

lines : line
      | lines line
      ;

line : ignore_protocol
     | ignore_traffic
     | strip_nat
     | general
     | sync
     | stats
     ;

log : T_LOG T_PATH_VAL
{
	strncpy(conf.logfile, $2, FILENAME_MAXLEN);
};

lock : T_LOCK T_PATH_VAL
{
	strncpy(conf.lockfile, $2, FILENAME_MAXLEN);
};

strip_nat: T_STRIP_NAT
{
	fprintf(stderr, "Notice: StripNAT clause is obsolete. "
			"Please, remove it from conntrackd.conf\n");
};

refreshtime : T_REFRESH T_NUMBER
{
	conf.refresh = $2;
};

expiretime: T_EXPIRE T_NUMBER
{
	conf.cache_timeout = $2;
};

timeout: T_TIMEOUT T_NUMBER
{
	conf.commit_timeout = $2;
};

checksum: T_CHECKSUM T_ON 
{
	conf.mcast.checksum = 0;
};

checksum: T_CHECKSUM T_OFF
{
	conf.mcast.checksum = 1;
};

ignore_traffic : T_IGNORE_TRAFFIC '{' ignore_traffic_options '}';

ignore_traffic_options :
		       | ignore_traffic_options ignore_traffic_option;

ignore_traffic_option : T_IPV4_ADDR T_IP
{
	union inet_address ip;
	int family = 0;

	memset(&ip, 0, sizeof(union inet_address));

	if (inet_aton($2, &ip.ipv4))
		family = AF_INET;
#ifdef HAVE_INET_PTON_IPV6
	else if (inet_pton(AF_INET6, $2, &ip.ipv6) > 0)
		family = AF_INET6;
#endif

	if (!family) {
		fprintf(stdout, "%s is not a valid IP, ignoring", $2);
		return;
	}

	if (!STATE(ignore_pool)) {
		STATE(ignore_pool) = ignore_pool_create(family);
		if (!STATE(ignore_pool)) {
			fprintf(stdout, "Can't create ignore pool!\n");
			exit(EXIT_FAILURE);
		}
	}

	if (!ignore_pool_add(STATE(ignore_pool), &ip)) {
		if (errno == EEXIST)
			fprintf(stdout, "IP %s is repeated "
					"in the ignore pool\n", $2);
		if (errno == ENOSPC)
			fprintf(stdout, "Too many IP in the ignore pool!\n");
	}
};

multicast_line : T_MULTICAST '{' multicast_options '}';

multicast_options :
		  | multicast_options multicast_option;

multicast_option : T_IPV4_ADDR T_IP
{
	if (!inet_aton($2, &conf.mcast.in)) {
		fprintf(stderr, "%s is not a valid IPv4 address\n");
		return;
	}

        if (conf.mcast.ipproto == AF_INET6) {
		fprintf(stderr, "Your multicast address is IPv4 but "
		                "is binded to an IPv6 interface? Surely "
				"this is not what you want\n");
		return;
	}

	conf.mcast.ipproto = AF_INET;
};

multicast_option : T_IPV6_ADDR T_IP
{
#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, $2, &conf.mcast.in) <= 0)
		fprintf(stderr, "%s is not a valid IPv6 address\n", $2);
#endif

	if (conf.mcast.ipproto == AF_INET) {
		fprintf(stderr, "Your multicast address is IPv6 but "
				"is binded to an IPv4 interface? Surely "
				"this is not what you want\n");
		return;
	}

	conf.mcast.ipproto = AF_INET6;
};

multicast_option : T_IPV4_IFACE T_IP
{
	if (!inet_aton($2, &conf.mcast.ifa)) {
		fprintf(stderr, "%s is not a valid IPv4 address\n");
		return;
	}

        if (conf.mcast.ipproto == AF_INET6) {
		fprintf(stderr, "Your multicast interface is IPv4 but "
		                "is binded to an IPv6 interface? Surely "
				"this is not what you want\n");
		return;
	}

	conf.mcast.ipproto = AF_INET;
};

multicast_option : T_IPV6_IFACE T_IP
{
#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, $2, &conf.mcast.ifa) <= 0)
		fprintf(stderr, "%s is not a valid IPv6 address\n", $2);
#endif

	if (conf.mcast.ipproto == AF_INET) {
		fprintf(stderr, "Your multicast interface is IPv6 but "
				"is binded to an IPv4 interface? Surely "
				"this is not what you want\n");
		return;
	}

	conf.mcast.ipproto = AF_INET6;
};

multicast_option : T_IFACE T_STRING
{
	strncpy(conf.mcast.iface, $2, IFNAMSIZ);
};

multicast_option : T_BACKLOG T_NUMBER
{
	fprintf(stderr, "Notice: Backlog option inside Multicast clause is "
			"obsolete. Please, remove it from conntrackd.conf.\n");
};

multicast_option : T_GROUP T_NUMBER
{
	conf.mcast.port = $2;
};

hashsize : T_HASHSIZE T_NUMBER
{
	conf.hashsize = $2;
};

hashlimit: T_HASHLIMIT T_NUMBER
{
	conf.limit = $2;
};

unix_line: T_UNIX '{' unix_options '}';

unix_options:
	    | unix_options unix_option
	    ;

unix_option : T_PATH T_PATH_VAL
{
	strcpy(conf.local.path, $2);
};

unix_option : T_BACKLOG T_NUMBER
{
	conf.local.backlog = $2;
};

ignore_protocol: T_IGNORE_PROTOCOL '{' ignore_proto_list '}';

ignore_proto_list:
		 | ignore_proto_list ignore_proto
		 ;

ignore_proto: T_NUMBER
{
	if ($1 < IPPROTO_MAX)
		conf.ignore_protocol[$1] = 1;
	else
		fprintf(stdout, "Protocol number `%d' is freak\n", $1);
};

ignore_proto: T_UDP
{
	conf.ignore_protocol[IPPROTO_UDP] = 1;
};

ignore_proto: T_ICMP
{
	conf.ignore_protocol[IPPROTO_ICMP] = 1;
};

ignore_proto: T_VRRP
{
	conf.ignore_protocol[IPPROTO_VRRP] = 1;
};

ignore_proto: T_IGMP
{
	conf.ignore_protocol[IPPROTO_IGMP] = 1;
};

sync: T_SYNC '{' sync_list '}';

sync_list:
	 | sync_list sync_line;

sync_line: refreshtime
	 | expiretime
	 | timeout
	 | checksum
	 | multicast_line
	 | relax_transitions
	 | delay_destroy_msgs
	 | sync_mode_persistent
	 | sync_mode_nack
	 | listen_to
	 | state_replication
	 ;

sync_mode_persistent: T_SYNC_MODE T_PERSISTENT '{' sync_mode_persistent_list '}'
{
	conf.flags |= SYNC_MODE_PERSISTENT;
};

sync_mode_nack: T_SYNC_MODE T_NACK '{' sync_mode_nack_list '}'
{
	conf.flags |= SYNC_MODE_NACK;
};

sync_mode_persistent_list:
	      | sync_mode_persistent_list sync_mode_persistent_line;

sync_mode_persistent_line: refreshtime
              		 | expiretime
	     		 | timeout
			 | relax_transitions
			 | delay_destroy_msgs
			 ;

sync_mode_nack_list:
	      | sync_mode_nack_list sync_mode_nack_line;

sync_mode_nack_line: resend_buffer_size
		   | timeout
		   | window_size
		   ;

resend_buffer_size: T_RESEND_BUFFER_SIZE T_NUMBER
{
	conf.resend_buffer_size = $2;
};

window_size: T_WINDOWSIZE T_NUMBER
{
	conf.window_size = $2;
};

relax_transitions: T_RELAX_TRANSITIONS
{
	fprintf(stderr, "Notice: RelaxTransitions clause is obsolete. "
			"Please, remove it from conntrackd.conf\n");
};

delay_destroy_msgs: T_DELAY
{
	fprintf(stderr, "Notice: DelayDestroyMessages clause is obsolete. "
			"Please, remove it from conntrackd.conf\n");
};

listen_to: T_LISTEN_TO T_IP
{
	union inet_address addr;

#ifdef HAVE_INET_PTON_IPV6
	if (inet_pton(AF_INET6, $2, &addr.ipv6) <= 0)
#endif
		if (inet_aton($2, &addr.ipv4) <= 0) {
			fprintf(stderr, "%s is not a valid IP address\n", $2);
			exit(EXIT_FAILURE);
		}

	if (CONFIG(listen_to_len) == 0 || CONFIG(listen_to_len) % 16) {
		CONFIG(listen_to) = realloc(CONFIG(listen_to),
					    sizeof(union inet_address) *
					    (CONFIG(listen_to_len) + 16));
		if (CONFIG(listen_to) == NULL) {
			fprintf(stderr, "cannot init listen_to array\n");
			exit(EXIT_FAILURE);
		}

		memset(CONFIG(listen_to) + 
		       (CONFIG(listen_to_len) * sizeof(union inet_address)),
		       0, sizeof(union inet_address) * 16);

	}
};

state_replication: T_REPLICATE states T_FOR state_proto;

states:
      | states state;

state_proto: T_TCP;
state: tcp_state;

tcp_state: T_SYN_SENT
{
	extern struct state_replication_helper tcp_state_helper;
	state_helper_register(&tcp_state_helper, TCP_CONNTRACK_SYN_SENT);
};
tcp_state: T_SYN_RECV
{
	extern struct state_replication_helper tcp_state_helper;
	state_helper_register(&tcp_state_helper, TCP_CONNTRACK_SYN_RECV);
};
tcp_state: T_ESTABLISHED
{
	extern struct state_replication_helper tcp_state_helper;
	state_helper_register(&tcp_state_helper, TCP_CONNTRACK_ESTABLISHED);
};
tcp_state: T_FIN_WAIT
{
	extern struct state_replication_helper tcp_state_helper;
	state_helper_register(&tcp_state_helper, TCP_CONNTRACK_FIN_WAIT);
};
tcp_state: T_CLOSE_WAIT
{
	extern struct state_replication_helper tcp_state_helper;
	state_helper_register(&tcp_state_helper, TCP_CONNTRACK_CLOSE_WAIT);
};
tcp_state: T_LAST_ACK
{
	extern struct state_replication_helper tcp_state_helper;
	state_helper_register(&tcp_state_helper, TCP_CONNTRACK_LAST_ACK);
};
tcp_state: T_TIME_WAIT
{
	extern struct state_replication_helper tcp_state_helper;
	state_helper_register(&tcp_state_helper, TCP_CONNTRACK_TIME_WAIT);
};
tcp_state: T_CLOSE
{
	extern struct state_replication_helper tcp_state_helper;
	state_helper_register(&tcp_state_helper, TCP_CONNTRACK_CLOSE);
};
tcp_state: T_LISTEN
{
	extern struct state_replication_helper tcp_state_helper;
	state_helper_register(&tcp_state_helper, TCP_CONNTRACK_LISTEN);
};

general: T_GENERAL '{' general_list '}';

general_list:
	    | general_list general_line
	    ;

general_line: hashsize
	    | hashlimit
	    | log
	    | lock
	    | unix_line
	    | netlink_buffer_size
	    | netlink_buffer_size_max_grown
	    | family
	    ;

netlink_buffer_size: T_BUFFER_SIZE T_NUMBER
{
	conf.netlink_buffer_size = $2;
};

netlink_buffer_size_max_grown : T_BUFFER_SIZE_MAX_GROWN T_NUMBER
{
	conf.netlink_buffer_size_max_grown = $2;
};

family : T_FAMILY T_STRING
{
	if (strncmp($2, "IPv6", strlen("IPv6")) == 0)
		conf.family = AF_INET6;
	else
		conf.family = AF_INET;
};

stats: T_SYNC '{' stats_list '}';

stats_list:
	 | stats_list stat_line
	 ;

stat_line:
	 |
	 ;

%%

int
yyerror(char *msg)
{
	printf("Error parsing config file: ");
	printf("line (%d), symbol '%s': %s\n", yylineno, yytext, msg);
	exit(EXIT_FAILURE);
}

int
init_config(char *filename)
{
	FILE *fp;

	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	yyrestart(fp);
	yyparse();
	fclose(fp);

	/* default to IPv4 */
	if (CONFIG(family) == 0)
		CONFIG(family) = AF_INET;

	/* set to default is not specified */
	if (strcmp(CONFIG(lockfile), "") == 0)
		strncpy(CONFIG(lockfile), DEFAULT_LOCKFILE, FILENAME_MAXLEN);

	/* default to 180 seconds of expiration time: cache entries */
	if (CONFIG(cache_timeout) == 0)
		CONFIG(cache_timeout) = 180;

	/* default to 180 seconds: committed entries */
	if (CONFIG(commit_timeout) == 0)
		CONFIG(commit_timeout) = 180;

	/* default to 60 seconds of refresh time */
	if (CONFIG(refresh) == 0)
		CONFIG(refresh) = 60;

	if (CONFIG(resend_buffer_size) == 0)
		CONFIG(resend_buffer_size) = 262144;

	/* create empty pool */
	if (!STATE(ignore_pool)) {
		STATE(ignore_pool) = ignore_pool_create(CONFIG(family));
		if (!STATE(ignore_pool)) {
			fprintf(stdout, "Can't create ignore pool!\n");
			exit(EXIT_FAILURE);
		}
	}

	/* default to a window size of 20 packets */
	if (CONFIG(window_size) == 0)
		CONFIG(window_size) = 20;

	return 0;
}
