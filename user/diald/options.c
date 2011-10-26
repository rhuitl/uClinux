/*
 * options.c - Option parsing code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

#define MAXLINELEN 1024
#define MAXARGS 512


/* Configuration variables */
char device[10]; /* The Device tu use for MODE_DEV */
char device_node[9];
int  device_iface ;
char **devices = 0;
int device_count = 0;
int inspeed = DEFAULT_SPEED;
int window = 0;
int mtu = DEFAULT_MTU;
int mru = DEFAULT_MTU;
char *connector = 0;
char *disconnector = 0;
char *local_ip = 0;
unsigned long local_addr = 0;
char *orig_local_ip = 0;
char *netmask = 0;
char *remote_ip = 0;
char *orig_remote_ip = 0;
char *addroute = 0;
char *delroute = 0;
char *ip_up = 0;
char *ip_down = 0;
char *acctlog = 0;
char *pidlog = "diald.pid";
char *fifoname = 0;
char *lock_prefix = LOCK_PREFIX;
int pidstring = 1;
char *run_prefix = RUN_PREFIX;
char *path_route = PATH_ROUTE;
char *path_ifconfig = PATH_IFCONFIG;
char *path_bootpc = PATH_BOOTPC;
char *path_pppd = PATH_PPPD;
int buffer_packets = BUFFER_PACKETS;
int buffer_size = BUFFER_SIZE;
int buffer_fifo_dispose = BUFFER_FIFO_DISPOSE;
int buffer_timeout = BUFFER_TIMEOUT;
FILE *acctfp = 0;
int mode = MODE_SLIP;
int debug = 0;
int modem = 0;
int crtscts = 0;
#ifdef EMBED
int dodaemon = 0;
#else
int dodaemon = 1;
#endif /* EMBED */
int slip_encap = 0;
int lock_dev = 0;
int default_route = 0;
int dynamic_addrs = 0;
int dynamic_mode = DMODE_REMOTE_LOCAL;
int rotate_devices = 0;
int two_way = 0;
int give_way = 0;
int do_reroute = UNSAFE_ROUTING;
int proxyarp = 0;
int route_wait = 0;

int connect_timeout = 60;
int disconnect_timeout = 60;
int redial_timeout = DEFAULT_DIAL_DELAY;
int nodev_retry_timeout = 1;
int stop_dial_timeout = 60;
int kill_timeout = 60;
int start_pppd_timeout = 60;
int stop_pppd_timeout = 60;
int first_packet_timeout = DEFAULT_FIRST_PACKET_TIMEOUT;
int retry_count = 0;
int died_retry_count = 1;
int redial_backoff_start = -1;
int redial_backoff_limit = 600;
int dial_fail_limit = 0;

int metric = DEFAULT_INTERFACE_METRIC;
int drmetric = DEFAULT_DEFAULT_ROUTE_METRIC;

#ifdef SIOCSKEEPALIVE
int keepalive = 0;
#endif
#ifdef SIOCSOUTFILL
int outfill = 0;
#endif

struct {
    char *str;
    char *uargs;
    char args;
    void *var;
    void (*parser)();
} commands[] = {
    {"-f","<file>",1,0,read_config_file},
    {"-file","<file>",1,0,read_config_file},
    {"include","<file>",1,0,read_config_file},
/* Mode options */
    {"-m","[ppp|slip|cslip|slip6|cslip6|aslip|dev]",1,0,set_mode},
    {"mode","[ppp|slip|cslip|slip6|cslip6|aslip|dev]",1,0,set_mode},
/* Debugging options */
    {"debug","<debugmask>",1,&debug,set_int},
    {"-daemon","",0,&dodaemon,clear_flag},
/* Variable handling */
    {"set","<name> <value>",2,0,&parse_set},
/* general options */
    {"accounting-log","<f>",1,&acctlog,set_str},
    {"pidfile","<f>",1,&pidlog,set_str},
    {"fifo","<f>",1,&fifoname,set_str},
/* Networking addressing and control options */
    {"window","<n>",1,&window,set_int},
    {"mtu","<m>",1,&mtu,set_int},
    {"mru","<m>",1,&mru,set_int},
    {"local","<ip-address>",1,&local_ip,set_str},
    {"remote","<ip-address>",1,&remote_ip,set_str},
    {"netmask","<ip-address>",1,&netmask,set_str},
    {"dynamic","",0,&dynamic_addrs,set_flag},
    {"dslip-mode","<mode>",1,0,set_dslip_mode},
    {"defaultroute","",0,&default_route,set_flag},
    {"addroute","<script>",1,&addroute,set_str},
    {"delroute","<script>",1,&delroute,set_str},
    {"proxyarp","",0,&proxyarp,set_flag},
    {"ip-up","<script>",1,&ip_up,set_str},
    {"ip-down","<script>",1,&ip_down,set_str},
    {"reroute","",0,&do_reroute,set_flag},
    {"-reroute","",0,&do_reroute,clear_flag},
#ifdef SIOCSKEEPALIVE
    {"keepalive","<0-255>",1,&keepalive,set_int},
#endif
#ifdef SIOCSOUTFILL
    {"outfill","<0-255>",1,&outfill,set_int},
#endif
/* Modem options */
    {"device","<device>",1,0,add_device},
    {"connect","<script>",1,&connector,set_str},
    {"disconnect","<script>",1,&disconnector,set_str},
    {"lock","",0,&lock_dev,set_flag},
    {"speed","<baudrate>",1,&inspeed,set_int},
    {"modem","",0,&modem,set_flag},
    {"crtscts","",0,&crtscts,set_flag},
    {"rotate-devices","",0,&rotate_devices,set_flag},
/* Configuration options */
    {"lock-prefix","<path>",1,&lock_prefix,set_str},
    {"pidstring","",0,&pidstring,set_flag},
    {"-pidstring","",0,&pidstring,clear_flag},
    {"run-prefix","<path>",1,&run_prefix,set_str},
    {"path-route","<path>",1,&path_route,set_str},
    {"path-ifconfig","<path>",1,&path_ifconfig,set_str},
    {"path-bootpc","<path>",1,&path_bootpc,set_str},
    {"path-pppd","<path>",1,&path_pppd,set_str},
    {"buffer-packets","",0,&buffer_packets,set_flag},
    {"-buffer-packets","",0,&buffer_packets,clear_flag},
    {"buffer_size","<n>",1,&buffer_size,buffer_init},
    {"buffer-fifo-dispose","",0,&buffer_fifo_dispose,set_flag},
    {"-buffer-fifo-dispose","",0,&buffer_fifo_dispose,clear_flag},
    {"buffer-timeout","<n>",1,&buffer_timeout,set_int},
/* Timeouts and connection policy control */
    {"route-wait","",0,&route_wait,set_flag},
    {"two-way","",0,&two_way,set_flag},
    {"give-way","",0,&give_way,set_flag},
    {"connect-timeout","<timeout>",1,&connect_timeout,set_int},
    {"disconnect-timeout","<timeout>",1,&disconnect_timeout,set_int},
    {"redial-timeout","<timeout>",1,&redial_timeout,set_int},
    {"nodev-retry-timeout","<timeout>",1,&nodev_retry_timeout,set_int},
    {"stop-dial-timeout","<timeout>",1,&stop_dial_timeout,set_int},
    {"kill-timeout","<timeout>",1,&kill_timeout,set_int},
    {"start-pppd-timeout","<timeout>",1,&start_pppd_timeout,set_int},
    {"stop-pppd-timeout","<timeout>",1,&stop_pppd_timeout,set_int},
    {"first-packet-timeout","<timeout>",1,&first_packet_timeout,set_int},
    {"retry-count","<count>",1,&retry_count,set_int},
    {"died-retry-count","<count>",1,&died_retry_count,set_int},
    {"redial-backoff-start","<count>",1,&redial_backoff_start,set_int},
    {"redial-backoff-limit","<time>",1,&redial_backoff_limit,set_int},
    {"dial-fail-limit","<count>",1,&dial_fail_limit,set_int},
/* Filter rules */
    {"prule","<name> <protocol> <spec>",3,0,&parse_prule},
    {"var","<name> <spec>",2,0,&parse_var},
    {"restrict","<start-time> <end-time> <weekday> <day> <month>",5,0,&parse_restrict},
    {"or-restrict","<start-time> <end-time> <weekday> <day> <month>",5,0,&parse_or_restrict},
    {"bringup","<protocol-rule> <timeout> <packet-rule>",3,0,&parse_bringup},
    {"keepup","<protocol-rule> <timeout> <packet-rule>",3,0,&parse_keepup},
    {"accept","<protocol-rule> <timeout> <packet-rule>",3,0,&parse_accept},
    {"ignore","<protocol-rule> <packet-rule>",2,0,&parse_ignore},
    {"impulse","[<duration>,<fuzz>|<duration1>,<duration2>,<fuzz>]",1,0,&parse_impulse},
    {"up","",0,0,&parse_up},
    {"down","",0,0,&parse_down},
    {"flushfilters","",0,0,&flush_filters},
    {"flushprules","",0,0,&flush_prules},
    {"flushvars","",0,0,&flush_vars},
	{"metric","<m>",1,&metric,&set_int},
	{"drmetric","<m>",1,&drmetric,&set_int},
    {0,0,0,0}
};

void init_vars()
{
    devices = 0;
    device_count = 0;
    inspeed = DEFAULT_SPEED;
    window = 0;
    mtu = DEFAULT_MTU;
    mru = DEFAULT_MTU;
    connector = 0;
    disconnector = 0;
    local_ip = 0;
    local_addr = 0;
    orig_local_ip = 0;
    netmask = 0;
    remote_ip = 0;
    orig_remote_ip = 0;
    addroute = 0;
    delroute = 0;
    ip_up = 0;
    ip_down = 0;
    acctlog = 0;
    pidlog = "diald.pid";
    fifoname = 0;
    acctfp = 0;
    mode = MODE_SLIP;
    debug = 0;
    modem = 0;
    crtscts = 0;
    dodaemon = 1;
    slip_encap = 0;
    lock_dev = 0;
    default_route = 0;
    dynamic_addrs = 0;
    dynamic_mode = DMODE_REMOTE_LOCAL;
    rotate_devices = 0;
    two_way = 0;
    do_reroute = UNSAFE_ROUTING;
    proxyarp = 0;
    route_wait = 0;
    connect_timeout = 60;
    disconnect_timeout = 60;
    redial_timeout = DEFAULT_DIAL_DELAY;
    nodev_retry_timeout = 1;
    stop_dial_timeout = 60;
    kill_timeout = 60;
    start_pppd_timeout = 60;
    stop_pppd_timeout = 60;
    first_packet_timeout = DEFAULT_FIRST_PACKET_TIMEOUT;
    retry_count = 0;
    died_retry_count = 1;
    redial_backoff_start = -1;
    redial_backoff_limit = 600;
    dial_fail_limit = 0;
    lock_prefix = LOCK_PREFIX;
    pidstring = 1;
    run_prefix = RUN_PREFIX;
    path_route = PATH_ROUTE;
    path_ifconfig = PATH_IFCONFIG;
    path_bootpc = PATH_BOOTPC;
    path_pppd = PATH_PPPD;
    buffer_packets = BUFFER_PACKETS;
    buffer_size = BUFFER_SIZE;
    buffer_fifo_dispose = BUFFER_FIFO_DISPOSE;
    buffer_timeout = BUFFER_TIMEOUT;
#ifdef SIOCSKEEPALIVE
    keepalive = 0;
#endif
#ifdef SIOCSOUTFILL
    outfill = 0;
#endif
}

void set_int(int *var, char **argv)
{
    *var = atoi(*argv);
}

void set_str(char **var, char **argv)
{
    *var = strdup(*argv);
}

void set_mode(char **var, char **argv)
{
    if (strcmp(argv[0],"ppp") == 0)
	mode = MODE_PPP;
    else if (strcmp(argv[0],"dev") == 0)
	mode = MODE_DEV;
    else if (strcmp(argv[0],"slip") == 0)
	mode = MODE_SLIP, slip_encap = 0;
    else if (strcmp(argv[0],"cslip") == 0)
	mode = MODE_SLIP, slip_encap = 1;
    else if (strcmp(argv[0],"slip6") == 0)
	mode = MODE_SLIP, slip_encap = 2;
    else if (strcmp(argv[0],"cslip6") == 0)
	mode = MODE_SLIP, slip_encap = 3;
    else if (strcmp(argv[0],"aslip") == 0)
	mode = MODE_SLIP, slip_encap = 8;
    else
	syslog(LOG_ERR,"Unknown mode %s.\nValid modes are: dev, ppp, slip, cslip, slip6, cslip6, or aslip.",argv[0]);
}

void set_dslip_mode(char **var, char **argv)
{
    if (strcmp(argv[0],"remote") == 0)
	dynamic_mode = DMODE_REMOTE;
    else if (strcmp(argv[0],"local") == 0)
	dynamic_mode = DMODE_LOCAL;
    else if (strcmp(argv[0],"remote-local") == 0)
	dynamic_mode = DMODE_REMOTE_LOCAL;
    else if (strcmp(argv[0],"local-remote") == 0)
	dynamic_mode = DMODE_LOCAL_REMOTE;
    else if (strcmp(argv[0],"bootp") == 0)
	dynamic_mode = DMODE_BOOTP;
    else
	syslog(LOG_ERR,"Unknown dynamic slip mode %s.\nValid modes are: remote, local, remote-local, local-remote or bootp.",argv[0]);
}

void set_flag(int *var, char **argv)
{
    *var = 1;
}

void clear_flag(int *var, char **argv)
{
    *var = 0;
}

void read_config_file(int *var, char **argv)
{
    parse_options_file(argv[0]);
}

void usage(void)
{
    int i;
    syslog(LOG_ERR,"usage: diald [modem-device1] [modem-device2 ...] [options...] [-- [pppd options...]]\n");
    syslog(LOG_ERR,"where valid options are:");
    for (i = 0; commands[i].str; i++)
        syslog(LOG_ERR,"    %s %s",commands[i].str,commands[i].uargs);
    exit(1);
}

void copy_pppd_args(int argc, char *argv[])
{
    int i;
#ifdef NO_MEM_LEAKS
    if (pppd_argv) {
	while (i = 0; i < argc; i++)
	    free(pppd_argv[i]);
	free(pppd_argv);
    }
#endif
    pppd_argv = malloc(sizeof(char **)*argc);
    for (i = 0; i < argc; i++) {
	pppd_argv[i] = strdup(argv[i]);
    }
    pppd_argc = argc;
}

void add_device(void *var, char **argv)
{
    device_count++;
    if (device_count == 1)
    	devices = (char **)malloc(sizeof(char *));
    else
	devices = (char **)realloc(devices,sizeof(char *)*device_count);
    devices[device_count-1] = strdup(argv[0]);
}


void parse_args(int argc, char *argv[])
{
    int i;
    struct stat st;

    /* Get any tty devices from the initial arguments */
    for (i = 0; argc > 0 && stat(*argv,&st) == 0 && S_ISCHR(st.st_mode); i++) {
	add_device(0,argv);
	argc--, argv++;
    }
    
    /*
     * Ok, parse the options list now,
     * command line options override/augment defaults
     */
    while (argc-- > 0) {
	if (strcmp(*argv,"--") == 0) {
	    argv++;
	    argc--;
	    break;
	}
	for (i = 0; commands[i].str; i++)
	    if (strcmp(commands[i].str,*argv) == 0)
		break;
	if (commands[i].parser) {
	    argc -= commands[i].args;
	    if (argc < 0) {
		syslog(LOG_ERR,"Insufficient arguments to option '%s'",*argv);
		usage();
	    }
	    (commands[i].parser)(commands[i].var,++argv);
	    argv += commands[i].args;
	} else {
	    syslog(LOG_ERR,"Unknown option '%s'",*argv);
	    usage();
	}
    }
    /* Any remaining options are food for pppd */
    if (++argc > 0)
    	copy_pppd_args(argc,argv);
}

/* Parse the given options file */
void parse_options_file(char *file)
{
    char line[MAXLINELEN];
    char *argv[MAXARGS];
    char *s;
    char *t1,*t2;

    int argc, i;
    FILE *fp = fopen(file,"r");

    if (fp == NULL) {
	syslog(LOG_INFO, "Ignoring missing options file %s",file);
	return;	/* no options file */
    }
    while (fscanf(fp,"%1024[^\n]\n",line) != -1) {
	argc = 0;
	for (s = line, argc = 0; *s && argc < MAXARGS; s++) {
	    if (*s == ' ' || *s == '\t')
		*s = 0;
	    else if (*s == '#' && argc == 0) /* the line is a comment */
		goto comment;
	    else if (*s == '\"' || *s == '\'') {
		char delim = *s;
		/* start of a quoted argument */
		s++;
		argv[argc] = s;
		while (*s) {
		    if (*s == delim) { *s++ = 0; break; }
		    if (*s == '\\' && s[1] != 0) s++;
		    s++;
		}
		s--;
		/* go back and fix up "quoted" characters */
		t1 = t2 = argv[argc++];
		while (*t1) {
		   if (*t1 == '\\') {
			t1++;
			/* do a translation */
			switch (*t1) {
			case 'a': *t1 = '\a'; break;
			case 'b': *t1 = '\b'; break;
			case 'f': *t1 = '\f'; break;
			case 'n': *t1 = '\n'; break;
			case 'r': *t1 = '\r'; break;
			case 's': *t1 = ' '; break;
			case 't': *t1 = '\t'; break;
			default:
			    if (*t1 >= '0' && *t1 <= '8') {
				int val = 0, n;
				for (n = 0;
				n < 3 && (*t1 >= '0' && *t1 <= '8');
				++n) {
				    val = (val << 3) + (*t1 & 07);
				    t1++;
				}
				*(--t1) = val;
				break;
			    }
			    if (*t1 == 'x') {
				int val = 0, n, digit;
				t1++;
				for (n = 0; n < 2 && isxdigit(*t1); ++n) {
				    digit = toupper(*t1) -'0';
				    if (digit > 10)
					digit += '0' + 10 - 'A';
				    val = (val << 4) + digit;
				    t1++;
				}
				*(--t1) = val;
				break;
			    }
			    /* character is itself, don't muck with it. */
			}
		   }
		   *t2++ = *t1++;
		}
		*t2++ = 0;
	    } else { /* just a normal word */
		argv[argc++] = s;
		while (*s) {
		    if (*s == ' ' || *s == '\t') break;
		    s++;
		}
		s--;
	    }
	}
	*s = 0;

	if (argc == 0)
		goto comment;
	for (i = 0; commands[i].str; i++)
	    if (strcmp(commands[i].str,argv[0]) == 0)
		break;
	if (commands[i].parser) {
	    argc -= commands[i].args + 1;
	    if (argc < 0) {
		syslog(LOG_ERR,"Insufficient arguments to option '%s'",argv[0]);
	    } else {
	        (commands[i].parser)(commands[i].var,&argv[1]);
	    }
	} else if (strcmp("pppd-options",argv[0]) == 0) {
		copy_pppd_args(argc-1,&argv[1]);
	} else {
	    syslog(LOG_ERR,"Unknown option '%s'",*argv);
	}
comment:;
    }
    fclose(fp);
}

void check_setup()
{
    struct stat st;
    int i;
    int flag = 0;
    int temp ;
    char *p ;

    if (device_count == 0) {
	syslog(LOG_ERR,
	    "No device specified. You must have at least one device!");
	flag = 1;
	exit(1);
    }

    /* If for MODE_DEV then remove the /dev/ */
    strcpy(device , strrchr(devices[0],'/')+1 );
	
    temp = strcspn(device, "0123456789" ) ;
    strncpy(device_node , device , temp ) ;
    p = device + temp;
    device_iface = atoi( p );

    if (mode != MODE_DEV)
	for (i = 0; i < device_count; i++)
	    if (stat(devices[i],&st) < 0 || !S_ISCHR(st.st_mode))
		flag = 1,
		syslog(LOG_ERR,
		    "Specified device '%s' not a character device.",devices[0]);

    if (!connector)
	flag = 1,
	syslog(LOG_ERR,
	    "You must define a connector script (option 'connect').");
    if (!remote_ip)
	flag = 1, syslog(LOG_ERR,"You must define the remote ip address.");
    else if (inet_addr(remote_ip) == -1)
	flag = 1, syslog(LOG_ERR,"Bad remote ip address specification.");
    if (!local_ip)
	flag = 1, syslog(LOG_ERR,"You must define the local ip address.");
    else if (inet_addr(local_ip) == -1)
	flag = 1, syslog(LOG_ERR,"Bad local ip address specification.");
    else
    	local_addr = inet_addr(local_ip);

    if (acctlog) {
	if ((acctfp = fopen(acctlog,"a")) == NULL)
	    syslog(LOG_ERR,"Can't open accounting log file %s: %m",acctlog);
    	else
	    fclose(acctfp);
    }
    
    if (flag) exit(1);
}
