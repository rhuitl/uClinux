/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/*
 *
 * Program: Snort
 *
 * Purpose: Check out the README file for info on what you can do
 *          with Snort.
 *
 * Author: Martin Roesch (roesch@clark.net)
 *
 * Comments: Ideas and code stolen liberally from Mike Borella's IP Grab
 *           program. Check out his stuff at http://www.borella.net.  I
 *           also have ripped some util functions from TCPdump, plus Mike's
 *           prog is derived from it as well.  All hail TCPdump....
 *
 */

/*  I N C L U D E S  **********************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef TIMESTATS
#include <signal.h> /* added for new hourly stats function in util.c */
#include <time.h>   /* added for new time stats function in util.c */
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <sys/stat.h>
#ifndef WIN32
#include <grp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif  /* !WIN32 */
#ifdef HAVE_GETOPT_LONG
//#define _GNU_SOURCE
/* A GPL copy of getopt & getopt_long src code is now in sfutil */
#undef HAVE_GETOPT_LONG
#endif
#include <getopt.h>
#include <timersub.h>
#include <setjmp.h>

#include "snort.h"
#include "rules.h"
#include "plugbase.h"
#include "signal.h"
#include "debug.h"
#include "util.h"
#include "parser.h"
#include "tag.h"
#include "log.h"
#include "detect.h"
#include "mstring.h"
#include "fpcreate.h"
#include "fpdetect.h"
#include "sfthreshold.h"
#include "packet_time.h"
#include "src/preprocessors/flow/flow_print.h"
#include "src/detection-plugins/sp_flowbits.h"
#include "src/preprocessors/spp_perfmonitor.h"
#include "mempool.h"
#include "sfutil/bitop_funcs.h"

#ifdef HAVE_LIBPRELUDE
 #include "src/output-plugins/spo_alert_prelude.h"
#endif

#include "event_queue.h"
#include "asn1.h"
#include "inline.h"
#include "mpse.h"
#include "generators.h"
#include "ipv6.h"

#ifdef DYNAMIC_PLUGIN
#include "dynamic-plugins/sf_dynamic_engine.h"
#include "dynamic-plugins/sf_dynamic_detection.h"
#define PROFILE_PREPROCS_NOREDEF
#include "dynamic-plugins/sf_dynamic_preprocessor.h"
#include "dynamic-plugins/sp_preprocopt.h"
#endif

/* Undefine the one from sf_dynamic_preprocessor.h */
#include "profiler.h"
#ifdef PERF_PROFILING
extern PreprocStats detectPerfStats, decodePerfStats,
       totalPerfStats, eventqPerfStats, rulePerfStats, mpsePerfStats;
#endif

extern char *optarg;                /* for getopt */
extern int   optind,opterr,optopt;  /* for getopt */

extern char *file_name;        /* parser.c - current rules file being processed */
extern int file_line;          /* parser.c - current line being processed in the rules */

/* set/cleared in otnx_match */
OptTreeNode * current_otn=0;

/*
 * used to identifiy code in use when segv signal happened
 * SIGLOC_xxxx
 */
enum { SIGLOC_PARSE_RULES_FILE=1, SIGLOC_PCAP_LOOP };
int signal_location=0;


#ifndef DLT_LANE8023
/*
 * Old OPEN BSD Log format is 17.
 * Define DLT_OLDPFLOG unless DLT_LANE8023 (Suse 6.3) is already
 * defined in bpf.h.
 */
#define DLT_OLDPFLOG 17
#endif

/*  G L O B A L S  ************************************************************/
extern OutputFuncNode *AlertList;
extern OutputFuncNode *LogList;

#ifdef TIMESTATS
long start_time;    /* tracks how many seconds snort actually ran */
#endif

extern int errno;
/*extern char *malloc_options;*/

/* exported variables *********************************************************/
u_int8_t runMode = 0;   /* snort run mode */
PV pv;                  /* program vars */
int datalink;           /* the datalink value */
char *progname;         /* name of the program (from argv[0]) */
char **progargs;
char *username;
char *groupname;
unsigned long userid = 0;
unsigned long groupid = 0;
struct passwd *pw;
struct group *gr;
char *pcap_cmd;         /* the BPF command string */
char *pktidx;           /* index ptr for the current packet */
pcap_t *pd = NULL;      /* pcap handle */

int g_drop_pkt;        /* inline drop pkt flag */ 
int g_pcap_test;       /* pcap test mode */

/* deprecated? */
FILE *alert;            /* alert file ptr */
FILE *binlog_ptr;       /* binary log file ptr */
int flow;               /* flow var (probably obsolete) */
int thiszone;           /* time zone info */
PacketCount pc;         /* packet count information */
u_long netmasks[33];    /* precalculated netmask array */
struct pcap_pkthdr *g_pkthdr;   /* packet header ptr */
u_char *g_pkt;          /* ptr to the packet data */
u_long g_caplen;        /* length of the current packet */
char *protocol_names[256];
u_int snaplen = SNAPLEN;


grinder_t grinder;
runtime_config snort_runtime;   /* run-time configuration struct */


/*
 * you may need to adjust this on the systems which don't have standard
 * paths defined
 */
#ifndef _PATH_VARRUN
char _PATH_VARRUN[STD_BUF];
#endif

SFPERF sfPerf;

/* locally defined functions **************************************************/
static char *ConfigFileSearch();
static int ProcessAlertCommandLine();
static int ProcessLogCommandLine();
static void Restart();
#ifdef DYNAMIC_PLUGIN
static void LoadDynamicPlugins();
#endif
static void PrintVersion();
#ifdef INLINE_FAILOPEN
void *InlinePatternMatcherInitThread(void *arg);
void PcapIgnorePacket(char *user, struct pcap_pkthdr * pkthdr, u_char * pkt);
#endif

/* Signal handler declarations ************************************************/
static void SigTermHandler(int signal);
static void SigIntHandler(int signal);
static void SigQuitHandler(int signal);
static void SigHupHandler(int signal);
static void SigUsrHandler(int signal);
#ifdef CATCH_SEGV
static void SigSegvHandler(int signal);
#else
#ifndef WIN32
#include <sys/resource.h>
#endif
#endif

/*
 *  Check for SIGHUP and invoke restart to
 *  cleanup
 */
int hup_check()
{
    int quiet_flag = pv.quiet_flag;

    if (pv.usr_signal == SIGHUP)
    {
        pv.quiet_flag = 0;
        LogMessage("*** Caught Hup-Signal\n");
        Restart();
        pv.quiet_flag = quiet_flag;
        pv.usr_signal = 0;
        pv.restart_flag = 1;
        return 1;
    }

    return 0;
}

/*
 *  Check for signal activity 
 */
static int exit_logged = 0;
int sig_check()
{
        int quiet_flag = pv.quiet_flag;
        pv.quiet_flag = 0;

        switch (pv.exit_signal)
        {
#ifndef DEBUG
            case SIGSEGV:
            case SIGFPE:
                /* Try to exit cleanly -- if this fails and we get
                 * another signal, we'll exit immediately.  */
                CleanExit(1);
                return 2;
                break;
#endif
            case SIGTERM:
                if (!exit_logged)
                {
                    LogMessage("*** Caught Term-Signal\n");
                    exit_logged = 1;
                }
                CleanExit(0);
                return 1;
                break;
            case SIGINT:
                if (!exit_logged)
                {
                    LogMessage("*** Caught Int-Signal\n");
                    exit_logged = 1;
                }
                CleanExit(0);
                return 1;
                break;
            case SIGQUIT:
                if (!exit_logged)
                {
                    LogMessage("*** Caught Quit-Signal\n");
                    exit_logged = 1;
                }
                CleanExit(0);
                return 1;
                break;
            case 0:
            default:
                break;
        }
        pv.exit_signal = 0;

        switch (pv.usr_signal)
        {
            case SIGUSR1:
                LogMessage("*** Caught Usr-Signal\n");
                DropStats(0);
                break;
            case SIGNAL_SNORT_ROTATE_STATS:
                LogMessage("*** Caught Usr-Signal: 'Rotate Stats'\n");
                pv.rotate_perf_file = 1;
                break;
            case SIGHUP:
                pv.quiet_flag = quiet_flag;
                return 1;
                break;
        }
        pv.quiet_flag = quiet_flag;
        pv.usr_signal = 0;

        return 0;
}

/*
 *
 * Function: main(int, char *)
 *
 * Purpose:  Handle program entry and exit, call main prog sections
 *           This can handle both regular (command-line) style
 *           startup, as well as Win32 Service style startup.
 *
 * Arguments: See command line args in README file
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 */
int main(int argc, char* argv[]) 
{
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    /* Do some sanity checking, because some people seem to forget to
     * put spaces between their parameters
     */
    if( argc > 1 &&
        ( _stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_INSTALL_CMDLINE_PARAM))==0   ||
          _stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_UNINSTALL_CMDLINE_PARAM))==0 ||
          _stricmp(argv[1], (SERVICE_CMDLINE_PARAM SERVICE_SHOW_CMDLINE_PARAM))==0       ) )
    {
        FatalError("You must have a space after the '%s' command-line parameter\n",
                   SERVICE_CMDLINE_PARAM);
        exit(0);
    }

    /* If the first parameter is "/SERVICE", then start Snort as a Win32 service */
    if( argc>1 && _stricmp(argv[1],SERVICE_CMDLINE_PARAM)==0)
    {
        return SnortServiceMain(argc, argv);
    }
#endif /* WIN32 && ENABLE_WIN32_SERVICE */

    return SnortMain(argc,argv);
}

/*
 *
 * Function: SnortMain(int, char *)
 *
 * Purpose:  The real place that the program handles entry and exit.  Called
 *           called by main(), or by SnortServiceMain().
 *
 * Arguments: See command line args in README file
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 */
int SnortMain(int argc, char *argv[])
{
#ifndef WIN32
#if defined(LINUX) || defined(FREEBSD) || defined(OPENBSD) || defined(SOLARIS) || defined(BSD) || defined(MACOS)
    sigset_t set;

    sigemptyset(&set);
#if defined(HAVE_LIBPRELUDE) || defined(INLINE_FAILOPEN)
    pthread_sigmask(SIG_SETMASK, &set, NULL);
#else
    sigprocmask(SIG_SETMASK, &set, NULL);
#endif /* HAVE_LIBPRELUDE || INLINE_FAILOPEN */
#else
    sigsetmask(0);
#endif /* LINUX, BSD, SOLARIS */
#endif  /* !WIN32 */

    /*    malloc_options = "AX";*/

    /* Make this prog behave nicely when signals come along.
     * Windows doesn't like all of these signals, and will
     * set errno for some.  Ignore/reset this error so it
     * doesn't interfere with later checks of errno value.
     */
    signal(SIGTERM, SigTermHandler);    if(errno!=0) errno=0;
    signal(SIGINT, SigIntHandler);      if(errno!=0) errno=0;
    signal(SIGQUIT, SigQuitHandler);    if(errno!=0) errno=0;
    signal(SIGHUP, SigHupHandler);      if(errno!=0) errno=0;
    signal(SIGUSR1, SigUsrHandler);    if(errno!=0) errno=0;
   
    signal(SIGNAL_SNORT_ROTATE_STATS, SigUsrHandler);
                                        if(errno!=0) errno=0;
#ifdef CATCH_SEGV
    signal(SIGSEGV,SigSegvHandler);  if(errno!=0) errno=0;
    signal(SIGFPE, SigSegvHandler);  if(errno!=0) errno=0;
#else
#ifdef NOCOREFILE
    {
        struct rlimit rlim;
        getrlimit(RLIMIT_CORE, &rlim);
        rlim.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &rlim);
    }
#endif
#endif

    /*
     * set a global ptr to the program name so other functions can tell what
     * the program name is
     */
    progname = argv[0];
    progargs = argv;

#ifdef WIN32
    if (!init_winsock())
        FatalError("Could not Initialize Winsock!\n");
#endif

    memset(&pv, 0, sizeof(PV));
    
    /*
     * setup some lookup data structs
     */
    InitNetmasks();
    InitProtoNames();

    /*
    **  This intializes the detection engine for later configuration
    */
    /* TODO: only do this when we know we are going into IDS mode */
    fpInitDetectionEngine();

    /* initialize the packet counter to loop forever */
    pv.pkt_cnt = -1;

    /* set the alert filename to NULL */
    pv.alert_filename = NULL;

    /* set the default alert mode */
    pv.alert_mode = ALERT_FULL;

    /* set the default assurance mode (used with stream 4) */
    pv.assurance_mode = ASSURE_ALL;

    pv.use_utc = 0;

    pv.log_mode = 0;

    /*
     * provide (limited) status messages by default
     */
    pv.quiet_flag = 0;

    /* initialize "rotate performance stats file" flag */
    pv.rotate_perf_file = 0;

    InitDecoderFlags();
    
    /* turn on checksum verification by default */
    pv.checksums_mode = DO_IP_CHECKSUMS | DO_TCP_CHECKSUMS |
                        DO_UDP_CHECKSUMS | DO_ICMP_CHECKSUMS;

    /* Default event log ID of instance 0 on CPU 0 */
    pv.event_log_id = 0x0000;

    /* Default limit on tagged packets */
    pv.tagged_packet_limit = 256;

    pv.default_rule_state = RULE_STATE_ENABLED;

#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    /* initialize flags which control the Win32 service */
    pv.terminate_service_flag = 0;
    pv.pause_service_flag = 0;
#endif  /* WIN32 && ENABLE_WIN32_SERVICE */

#ifdef DYNAMIC_PLUGIN
    /* Initialize storage space for preprocessor defined rule options */
    PreprocessorRuleOptionsInit();
#endif

    /* Initialize max frag hash for the BSD IPv6 fragmentation exploit */
    pv.ipv6_max_frag_sessions = 10000;
    /* This is the default timeout on BSD */
    pv.ipv6_frag_timeout = 60;

    /* chew up the command line */
    ParseCmdLine(argc, argv);

    /* If we are running non-root, install a dummy handler instead. */
    if (userid != 0)
        signal(SIGHUP, SigCantHupHandler);
    
    /* determine what run mode we are going to be in */
    if(pv.test_mode_flag)
    {
        if(!pv.quiet_flag)
        {
            if (pv.config_file)
                LogMessage("Running in Test mode with config file: %s\n",
                    pv.config_file);
            else if((pv.config_file = ConfigFileSearch()))
                LogMessage("Running in Test mode with inferred config file: %s\n",
                    pv.config_file);
        }
    }

    if(pv.print_version)
    {
        /* Do nothing, just fall through */
        runMode = MODE_VERSION;
    }
#ifdef DYNAMIC_PLUGIN
    else if(pv.dump_dynamic_rules_flag)
    {
        runMode = MODE_RULE_DUMP;
        if(!pv.quiet_flag)
        {
            if (pv.config_file)
                LogMessage("Running in Rule Dump mode with config file: %s\n",
                    pv.config_file);
        }
    }
#endif
    else if(pv.config_file)
    {
        runMode = MODE_IDS;
        if(!pv.quiet_flag)
            LogMessage("Running in IDS mode\n");
    }
    else if(pv.log_mode || pv.log_dir)
    {
        runMode = MODE_PACKET_LOG;
        if(!pv.quiet_flag)
            LogMessage("Running in packet logging mode\n");
    }
    else if(pv.verbose_flag)
    {
        runMode = MODE_PACKET_DUMP;
        if(!pv.quiet_flag)
            LogMessage("Running in packet dump mode\n");
    }
    else if((pv.config_file = ConfigFileSearch()))
    {
        runMode = MODE_IDS;
        if(!pv.quiet_flag)
            LogMessage("Running in IDS mode with inferred config file: %s\n",
                    pv.config_file);
    }
    else
    {
        /* unable to determine a run mode */
        DisplayBanner();
        ShowUsage(progname);
        PrintError("\n\nUh, you need to tell me to do something...\n\n");
        exit(1);
    }
     
    
    /* set the default logging dir if not set yet */
    /* XXX should probably be done after reading config files */
    if(!pv.log_dir)
    {
        if(!(pv.log_dir = strdup(DEFAULT_LOG_DIR)))
            FatalError("Out of memory setting default log dir\n");
    }
    
    /*
    **  Validate the log directory for logging packets
    */
    /* 
     * MFR - 16/9/05 Changing to call CheckLogDir only in logger mode so
     * we don't bail by accident if there's a logdir config option in the
     * snort.conf file
     */
    if(runMode == MODE_PACKET_LOG)
    {
        CheckLogDir();
    
        if(!pv.quiet_flag)
        {
            LogMessage("Log directory = %s\n", pv.log_dir);
        }
    }

    /* if we are in packet log mode, make sure we have a logging mode set */
    if(runMode == MODE_PACKET_LOG && !pv.log_mode)
    {
        /* MFR - 16/9/05 Changing default logging mode to PCAP */
        pv.log_mode = LOG_PCAP;
    }
    
    /*
     * if we're not reading packets from a file, open the network interface
     * for reading.. (interfaces are being initalized before the config file
     * is read, so some plugins would be able to start up properly.
     */
#ifdef GIDS
#ifdef IPFW
    /* Check to see if we got a Divert port or not */
    if(!pv.divert_port)
    {
        pv.divert_port = 8000;
    }

#endif /* IPFW */

    if (InlineMode())
    {
        if (!(pv.test_mode_flag && pv.disable_inline_init_flag))
        {
            InitInline();
        }
    }
#endif /* GIDS */

    /* extract the config directory from the config filename */
    if(pv.config_file)
    {
        /* is there a directory seperator in the filename */
        if(strrchr(pv.config_file,'/'))
        {
            char *tmp;
            /* lazy way, we waste a few bytes of memory here */
            if(!(pv.config_dir = strdup(pv.config_file)))
                FatalError("Out of memory extracting config dir\n");

            tmp = strrchr(pv.config_dir,'/');
            *(++tmp) = '\0';
        }
        else
        {
#ifdef WIN32
        /* is there a directory seperator in the filename */
        if(strrchr(pv.config_file,'\\'))
        {
            char *tmp;
            /* lazy way, we waste a few bytes of memory here */
            if(!(pv.config_dir = strdup(pv.config_file)))
                FatalError("Out of memory extracting config dir\n");

            tmp = strrchr(pv.config_dir,'\\');
            *(++tmp) = '\0';
        }
        else
#endif
            if(!(pv.config_dir = strdup("./")))
                FatalError("Out of memory extracting config dir\n");
        }
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Config file = %s, config dir = "
                    "%s\n", pv.config_file, pv.config_dir););
    }

    /* XXX do this after reading the config file? */
    if(pv.use_utc == 1)
    {
        thiszone = 0;
    }
    else
    {
        /* set the timezone (ripped from tcpdump) */
        thiszone = gmt2local(0);
    }

    if(!pv.quiet_flag)
    {
        LogMessage("\n        --== Initializing Snort ==--\n");
    }

    
    if(runMode == MODE_IDS && pv.rules_order_flag)
    {
        if(!pv.quiet_flag)
        {
            LogMessage("Rule application order changed to Pass->Alert->Log\n");
        }
    }

    /*
     * if daemon mode requested, fork daemon first, otherwise on linux
     * interface will be reset.
     */
    if(pv.daemon_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Entering daemon mode\n"););
        openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON ); 
    }
    else if(pv.logtosyslog_flag)
    {
        openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON );
    }

#ifdef TIMESTATS
    /*
     * Establish a handler for SIGALRM signals
     */
    signal (SIGALRM, DropHourlyStats);

    /* Set an alarm to go off in approximately one hour... */
    alarm(3600);
#endif

    InitOutputPlugins();
    
    /*
     * If snort is not run with root priveleges, 
     * no interfaces will be defined, so user
     * beware if an iface_ADDRESS variable is used
     * in snort.conf and snort is not run as root
     * (even if just in read mode)
     */
    if (!pv.readmode_flag && (runMode != MODE_VERSION))
        DefineAllIfaceVars();

    /* if we're using the rules system, it gets initialized here */
    if(runMode == MODE_IDS || runMode == MODE_RULE_DUMP || runMode == MODE_VERSION)
    {
        /* initialize all the plugin modules */
        InitPreprocessors();
        InitPlugIns();
        InitTag();
#ifdef PERF_PROFILING
        /* Register the main high level perf stats */
        RegisterPreprocessorProfile("detect", &detectPerfStats, 0, &totalPerfStats);
        RegisterPreprocessorProfile("mpse", &mpsePerfStats, 1, &detectPerfStats);
        RegisterPreprocessorProfile("rule eval", &rulePerfStats, 1, &detectPerfStats);
        RegisterPreprocessorProfile("decode", &decodePerfStats, 0, &totalPerfStats);
        RegisterPreprocessorProfile("eventq", &eventqPerfStats, 0, &totalPerfStats);
        RegisterPreprocessorProfile("total", &totalPerfStats, 0, NULL);
#endif

#ifdef DEBUG
        DumpPreprocessors();
        DumpPlugIns();
        DumpOutputPlugins();
#endif

        /* setup the default rule action anchor points */
        CreateDefaultRules();

        /* rule order flag '-o' requested, moves pass before alert and drop */
        if(pv.rules_order_flag)
        {
#ifdef GIDS
            OrderRuleLists("activation dynamic pass drop sdrop reject alert log");
#else
            if(InlineMode())
                OrderRuleLists("activation dynamic pass drop alert log");
            else 
                OrderRuleLists("activation dynamic pass drop alert log");
#endif /* GIDS */
        }

        if( pv.alert_before_pass )
        {
#ifdef GIDS
            OrderRuleLists("activation dynamic drop sdrop reject alert pass log");
#else
            OrderRuleLists("activation dynamic drop alert pass log");
#endif
        }

        if(!(pv.quiet_flag && !pv.daemon_flag))
            LogMessage("Parsing Rules file %s\n", pv.config_file);

        if (pv.config_file)
        {
            signal_location = SIGLOC_PARSE_RULES_FILE;
            ParseRulesFile(pv.config_file, 0);
            signal_location = 0;
        }
        else
        {
           LogMessage("Rules File not specified, is this correct?\n");
        }
        /* XXX: Why are we doing this twice? */
        //CheckLogDir();

        LogMessage("Tagged Packet Limit: %d\n", pv.tagged_packet_limit);

        OtnXMatchDataInitialize();

        asn1_init_mem(512);

        ipv6_init(pv.ipv6_max_frag_sessions);

        /*
        **  Handles Fatal Errors itself.
        */
        SnortEventqInit();
        
#ifdef GIDS
#ifndef IPFW
        if (InlineMode())
        {
            if (!(pv.test_mode_flag && pv.disable_inline_init_flag))
            {
                InitInlinePostConfig();
            }
        }
#endif /* IPFW */
#endif /* GIDS */

        if(!(pv.quiet_flag && !pv.daemon_flag))
        {
            print_thresholding();
            printRuleOrder();
            LogMessage("Log directory = %s\n", pv.log_dir);
        }
    }

#ifdef DYNAMIC_PLUGIN
    LoadDynamicPlugins();
#endif

    /*
     *  Display snort version information here so that we can also show dynamic
     *  plugin versions, if loaded.
     */
    switch ( pv.print_version )
    {
        case 'V':
            PrintVersion();
            exit(0);
            break;
#ifdef WIN32
        case 'W':
            PrintVersion();
            PrintDeviceList(pv.interface);
            exit(0);
            break;
#endif
        case '?':
            PrintVersion();
            ShowUsage(progname);
            if ( optopt )
                exit(1);
            exit(0);
            break;
    }
    
#ifdef DYNAMIC_PLUGIN
    InitDynamicEngines();

    if (pv.dump_dynamic_rules_flag)
    {
        DumpDetectionLibRules();
        CleanExit(0);
    }

    InitDynamicPreprocessors();
    ConfigureDynamicPreprocessors();

    InitDynamicDetectionPlugins();
#endif
    MapPreprocessorIds();

    /* Check rule state lists, enable/disabled
     * and err on 'special' GID without OTN.
     */
    /* 
     * Modified toi use sigInfo.shared in otn instead of the GENERATOR ID  - man 
     */ 
    SetRuleStates();

    /* Verify the preprocessors are configured properly */
    CheckPreprocessorsConfig();

    /* Need to do this after dynamic detection stuff is initialized, too */
    FlowBitsVerify();

    if( pv.daemon_flag )
    {
        /* Test pcap open */
        /* Do it here, so that we FatalError before daemonizing
         * if pcap cannot be opened.
         */
        InitPcap( 1 );

        if (pd)
        {
            pcap_close(pd);
            pd = NULL;
        }
        GoDaemon();
    }

    /* If PCAP is not initialized (or closed prior to daemonizing),
     * do it here... */
    if (!pd)
        InitPcap( 0 );

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Setting Packet Processor\n"););

    /* set the packet processor (ethernet, slip, t/r, etc ) */
    SetPktProcessor();

    /* create the PID file */
    /* TODO should be part of the GoDaemon process */
    if((runMode == MODE_IDS) || pv.log_mode || pv.daemon_flag 
            || *pv.pidfile_suffix || pv.create_pid_file)
    {
        /* ... then create a PID file if not reading from a file */
        if (!pv.readmode_flag && (pv.daemon_flag || *pv.pidfile_suffix || pv.create_pid_file))
        {
#ifdef WIN32
            CreatePidFile("WIN32");
#else            
#ifdef GIDS
                if (InlineMode())
                {
                    if (pv.interface)
                    {
                        CreatePidFile(pv.interface);
                    }
                    else
                    {
                        CreatePidFile("inline");
                    }
                }
                else
                {
                    /* We need to create the PID over here too */    
                    CreatePidFile(pv.interface);
                }
#else
                CreatePidFile(pv.interface);
#endif /* GIDS */
                if (pv.daemon_flag)
                {
                    SignalWaitingParent();
                }
#endif /* WIN32 */
        }
    }

#ifndef WIN32
    /* Drop the Chrooted Settings */
    if(pv.chroot_dir)
        SetChroot(pv.chroot_dir, &pv.log_dir);
    /* Drop privileges if requested, when initialization is done */
    SetUidGid();
    
#endif /*WIN32*/

#ifdef HAVE_LIBPRELUDE
    AlertPreludeSetupAfterSetuid();
#endif
    
    /* 
     * if we are in IDS mode and either an alert option was specified on the
     * command line or we do not have any alert plugins active, set them up
     * now
     */
    if(runMode == MODE_IDS && !pv.test_mode_flag &&
       (pv.alert_cmd_override || !pv.alert_plugin_active))
    {
        ProcessAlertCommandLine();
    }

    /* 
     * if we are in IDS mode or packet log mode and either a log option was 
     * specified on the command line or we do not have any log plugins active, 
     * set them up now
     */
    if((runMode == MODE_IDS || runMode == MODE_PACKET_LOG) &&
            (pv.log_cmd_override || !pv.log_plugin_active))
    {
        ProcessLogCommandLine();
    }

    PostConfigInitPlugins();

#if defined(INLINE_FAILOPEN) && !defined(GIDS)
    if (InlineMode() && !pv.readmode_flag &&
        !pv.inline_failopen_disabled_flag &&
        !pv.test_mode_flag && pd)
    {
        /* If in inline mode, start a thread to handle the initialization
         * of the fast pattern matcher.  Then, loop, passing packets,
         * until that initialization is complete.
         */
        LogMessage("Fail Open Thread starting..\n");
        pv.initialization_done_flag = 0;
        if (pthread_create(&pv.pass_thread_id, NULL, InlinePatternMatcherInitThread, NULL))
        {
            ErrorMessage("Failed to start Fail Open Thread. Starting "
                    "normally\n");
            fpCreateFastPacketDetection();
        }
        else
        {
            while (!pv.pass_thread_running_flag)
            {
                /* wait for the thread to spin up */
                LogMessage("Waiting for Fail Open Thread to start...\n");
                sleep(1);
            }
            LogMessage("Fail Open Thread started %d (%d)\n",
                pv.pass_thread_id, pv.pass_thread_pid);

            pv.initialization_done_flag = 1;

            while (pv.pass_thread_running_flag)
            {
                int pcap_ret = pcap_dispatch(pd, 1,
                        (pcap_handler)PcapIgnorePacket, NULL);
                if (pcap_ret >= 0)
                {
                    //LogMessage("Inline Fail Open Thread read %d packets\n",
                        //pcap_ret);
                }
            }
            LogMessage("Fail Open Thread terminated, passed %d packets.\n",
                pv.pass_thread_pktcount);

            /* Okay, thread is gone, we can start up */
        }
    }
    else
    {
        fpCreateFastPacketDetection();
    }
#else
    /*
    **  Create Fast Packet Classification Arrays
    **  from RTN list.  These arrays will be used to
    **  classify incoming packets through protocol.
    */
    fpCreateFastPacketDetection();
#endif

    if(!pv.quiet_flag)
    {
        mpsePrintSummary();
    }

    if(!pv.quiet_flag)
    {
        LogMessage("\n        --== Initialization Complete ==--\n");
    }

    /* Tell 'em who wrote it, and what "it" is */
    if(!pv.quiet_flag)
    {
        PrintVersion();
    }

    if(pv.test_mode_flag)
    {
        LogMessage("\nSnort sucessfully loaded all rules and checked all rule "
                "chains!\n");
        CleanExit(0);
    }

    if(pv.daemon_flag)
    {
        LogMessage("Snort initialization completed successfully (pid=%u)\n",getpid());
    }
    
    
    if( getenv("PCAP_FRAMES") )
    {
        LogMessage("Using PCAP_FRAMES = %s\n", getenv("PCAP_FRAMES") );
    }
    else
    {
        LogMessage("Not Using PCAP_FRAMES\n" );
    }

#ifdef TIMESTATS
    start_time = time(&start_time); /* start counting seconds */
#endif

#ifdef GIDS
    if (InlineMode())
    {
#ifndef IPFW
        IpqLoop();
#else
        IpfwLoop();
#endif
    }
    else
    {
#endif /* GIDS */

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Entering pcap loop\n"););

        InterfaceThread(NULL);

#ifdef GIDS
    }
#endif /* GIDS */

    /* If we are exiting because of a HUP, re-exec ourselves */
    if (hup_check() || pv.restart_flag)
    {
        if (pv.daemon_flag)
        {
            char *arg;
            int argIndex = 0;
            for  (arg = progargs[argIndex]; arg; argIndex++)
            {
                if (!strcmp(progargs[argIndex], "--restart"))
                {
                    break;
                }
                if (!strcmp(progargs[argIndex], "-D"))
                {
                    /* Replace -D with --restart */
                    progargs[argIndex++] = strdup("--restart");
                    break;
                }
            }
        }

#ifdef PARANOID
        execv(progname, progargs);
#else
        execvp(progname, progargs);
#endif

        /* only get here if we failed to restart */
        LogMessage("Restarting %s failed: %s\n", progname, strerror(errno));
        if(pv.daemon_flag || pv.logtosyslog_flag)
        {
#ifndef WIN32
            closelog();
#endif
        }
        exit(-1);
    }
    
    if(pv.daemon_flag || pv.logtosyslog_flag)
    {
#ifndef WIN32
        closelog();
#endif
    }

    return 0;
}

#ifdef DYNAMIC_PLUGIN
static void LoadDynamicPlugins()
{
    u_int32_t i;
    
    /* Load the dynamic engines */
    for (i=0;i<pv.dynamicEngineCount;i++)
    {
        switch (pv.dynamicEngine[i]->type)
        {
            case DYNAMIC_ENGINE_FILE:
                LoadDynamicEngineLib(pv.dynamicEngine[i]->path, 0);
                break;
            case DYNAMIC_ENGINE_DIRECTORY:
                LoadAllDynamicEngineLibs(pv.dynamicEngine[i]->path);
                break;
        }
    }

    /* Load the dynamic detection libs */
    for (i=0;i<pv.dynamicLibraryCount;i++)
    {
        switch (pv.dynamicDetection[i]->type)
        {
            case DYNAMIC_LIBRARY_FILE:
                LoadDynamicDetectionLib(pv.dynamicDetection[i]->path, 0);
                break;
            case DYNAMIC_LIBRARY_DIRECTORY:
                LoadAllDynamicDetectionLibs(pv.dynamicDetection[i]->path);
                break;
        }
    }

    /* Load the dynamic preprocessors */
    for (i=0;i<pv.dynamicPreprocCount;i++)
    {
        switch (pv.dynamicPreprocs[i]->type)
        {
            case DYNAMIC_PREPROC_FILE:
                LoadDynamicPreprocessor(pv.dynamicPreprocs[i]->path, 0);
                break;
            case DYNAMIC_PREPROC_DIRECTORY:
                LoadAllDynamicPreprocessors(pv.dynamicPreprocs[i]->path);
                break;
        }
    }
}
#endif


#ifdef DYNAMIC_PLUGIN
static void DisplayDynamicPluginVersions()
{
    void *lib = NULL;
    DynamicPluginMeta *meta;

    RemoveDuplicateEngines();
    RemoveDuplicateDetectionPlugins();
    RemoveDuplicatePreprocessorPlugins();

    lib = GetNextEnginePluginVersion(NULL);
    while ( lib != NULL )
    {
        meta = GetDetectionPluginMetaData(lib);

        fprintf(stderr, "           Rules Engine: %s  Version %d.%d  <Build %d>\n",
                    meta->uniqueName, meta->major, meta->minor, meta->build);
        lib = GetNextEnginePluginVersion(lib);
    }
    
    lib = GetNextDetectionPluginVersion(NULL);
    while ( lib != NULL )
    {
        meta = GetEnginePluginMetaData(lib);

        fprintf(stderr, "           Rules Object: %s  Version %d.%d  <Build %d>\n",
                    meta->uniqueName, meta->major, meta->minor, meta->build);
        lib = GetNextDetectionPluginVersion(lib);
    }    
    
    lib = GetNextPreprocessorPluginVersion(NULL);
    while ( lib != NULL )
    {
        meta = GetPreprocessorPluginMetaData(lib);

        fprintf(stderr, "           Preprocessor Object: %s  Version %d.%d  <Build %d>\n",
                    meta->uniqueName, meta->major, meta->minor, meta->build);
        lib = GetNextPreprocessorPluginVersion(lib);
    }    
}
#endif

static void PrintVersion()
{
    DisplayBanner();
    
#ifdef DYNAMIC_PLUGIN
    //  Get and print out library versions
    DisplayDynamicPluginVersions();
#endif

}

/*
 */
void PcapProcessPacket(char *user, struct pcap_pkthdr * pkthdr, u_char * pkt)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(totalPerfStats);
    
    /* First thing we do is process a Usr signal that we caught */
    if( sig_check() )
    {
        PREPROC_PROFILE_END(totalPerfStats);
        return;
    }
    pc.total++;

    /*
    ** Save off the time of each and every packet 
    */ 
    packet_time_update(pkthdr->ts.tv_sec);


    /* reset the thresholding subsystem checks for this packet */
    sfthreshold_reset();

    PREPROC_PROFILE_START(eventqPerfStats);
    SnortEventqReset();
    PREPROC_PROFILE_END(eventqPerfStats);

#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    if( pv.terminate_service_flag || pv.pause_service_flag )
    {
        //ClearDumpBuf();  /* cleanup and return without processing */
        return;
    }
#endif  /* WIN32 && ENABLE_WIN32_SERVICE */

    ProcessPacket(user, pkthdr, pkt, NULL);
    
    /* Collect some "on the wire" stats about packet size, etc */
    UpdateWireStats(&(sfPerf.sfBase), pkthdr->caplen);

    PREPROC_PROFILE_END(totalPerfStats);
    return;
}

/* 
 * This function is used below in ProcessPacket to manage the
 * freeing of the packetBitOp.pucBitBuffer before the local
 * packetBitOp goes out of scope.
 * If BitOpBucket is not NULL it is assumed that the pucBitBuffer
 * for the packetBitOp came from the MemPool otherwise it is 
 * assumed that boInitBITOP was used to allocate the pucBitBuffer
 * in which case the memory is freed.
 */
static INLINE void free_packetBitOp(BITOP *BitOp, MemPool *BitOpPool, MemBucket *BitOpBucket)
{
    if (BitOpBucket && BitOpPool)
        mempool_free(BitOpPool, BitOpBucket);
    else if (BitOp && BitOp->pucBitBuffer)
        boFreeBITOP(BitOp);

    if (BitOp != NULL)
        BitOp->pucBitBuffer = NULL;
}

static MemPool bitop_pool;
static PoolCount num_bitops = 4;
static int s_bitOpInit = 0;
static unsigned int bitop_numbits;

extern unsigned int num_preprocs; /* from plugbase.c */

void ProcessPacket(char *user, struct pcap_pkthdr * pkthdr, u_char * pkt, void *ft)
{
    Packet p;
    MemBucket *bitop_bucket = NULL;
    BITOP packetBitOp;

    if (!s_bitOpInit)
    {
        unsigned int bitop_numbytes;

        bitop_numbits = num_preprocs + 1;
        bitop_numbytes = bitop_numbits >> 3;

        if(bitop_numbits & 7) 
            bitop_numbytes++;

        if (mempool_init(&bitop_pool, num_bitops, bitop_numbytes) == 1)
            FatalError("Out of memory initializing BitOp memory pool\n");

        s_bitOpInit = 1;
    }

    /* reset the packet flags for each packet */
    p.packet_flags = 0;
#ifndef GIDS
    g_drop_pkt = 0;
#endif

    /* call the packet decoder */
    (*grinder) (&p, pkthdr, pkt);

    if(!p.pkth || !p.pkt)
    {
        return;
    }

    bitop_bucket = mempool_alloc(&bitop_pool);
    if (bitop_bucket == NULL)
    {
        memset(&packetBitOp, 0, sizeof(packetBitOp));
        boInitBITOP(&packetBitOp, bitop_numbits);
    }
    else 
    {
        boInitStaticBITOP(&packetBitOp, bitop_pool.obj_size, (unsigned char *)bitop_bucket->data);
    }

    p.preprocessor_bits = &packetBitOp;

    /* Make sure this packet skips the rest of the preprocessors */
    /* Remove once the IPv6 frag code is moved into frag 3 */
    if(p.packet_flags & PKT_NO_DETECT)
    {
        DisableAllDetect(&p);
    }


#ifdef GRE
    if (ft && p.greh == NULL)
#else
    if (ft)
#endif
    {
        p.packet_flags |= PKT_REBUILT_FRAG;
        p.fragtracker = ft;
    }

    /* print the packet to the screen */
    if(pv.verbose_flag)
    {
        if(p.iph != NULL)
            PrintIPPkt(stdout, p.iph->ip_proto, &p);
        else if(p.ah != NULL)
            PrintArpHeader(stdout, &p);
        else if(p.eplh != NULL)
        {
            PrintEapolPkt(stdout, &p);
        }
        else if(p.wifih && pv.showwifimgmt_flag)
        {
            PrintWifiPkt(stdout, &p);
        }
    }

    switch(runMode)
    {
        case MODE_PACKET_LOG:
            CallLogPlugins(&p, NULL, NULL, NULL);
            break;
        case MODE_IDS:
            /* allow the user to throw away TTLs that won't apply to the
               detection engine as a whole. */
            if(pv.min_ttl && p.iph != NULL && (p.iph->ip_ttl < pv.min_ttl))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                            "MinTTL reached in main detection loop\n"););

                free_packetBitOp(&packetBitOp, &bitop_pool, bitop_bucket);
                return;
            } 
            
            /* just throw away the packet if we are configured to ignore this port */
            if ( p.packet_flags & PKT_IGNORE_PORT )
            {
                free_packetBitOp(&packetBitOp, &bitop_pool, bitop_bucket);
                return;
            }

            /* start calling the detection processes */
            Preprocess(&p);
            break;
        default:
            break;
    }

    free_packetBitOp(&packetBitOp, &bitop_pool, bitop_bucket);

    //ClearDumpBuf();
}


/*
 * Function: ShowUsage(char *)
 *
 * Purpose:  Display the program options and exit
 *
 * Arguments: progname => name of the program (argv[0])
 *
 * Returns: 0 => success
 */
int ShowUsage(char *progname)
{
    fprintf(stdout, "USAGE: %s [-options] <filter options>\n", progname);
#if defined(WIN32) && defined(ENABLE_WIN32_SERVICE)
    fprintf(stdout, "       %s %s %s [-options] <filter options>\n", progname
                                                                   , SERVICE_CMDLINE_PARAM
                                                                   , SERVICE_INSTALL_CMDLINE_PARAM);
    fprintf(stdout, "       %s %s %s\n", progname
                                       , SERVICE_CMDLINE_PARAM
                                       , SERVICE_UNINSTALL_CMDLINE_PARAM);
    fprintf(stdout, "       %s %s %s\n", progname
                                       , SERVICE_CMDLINE_PARAM
                                       , SERVICE_SHOW_CMDLINE_PARAM);
#endif

#ifdef WIN32
    #define FPUTS_WIN32(msg) fputs(msg,stdout)
    #define FPUTS_UNIX(msg)  NULL
    #define FPUTS_BOTH(msg)  fputs(msg,stdout)
#else
    #define FPUTS_WIN32(msg) 
    #define FPUTS_UNIX(msg)  fputs(msg,stdout)
    #define FPUTS_BOTH(msg)  fputs(msg,stdout)
#endif

    FPUTS_BOTH ("Options:\n");
    FPUTS_BOTH ("        -A         Set alert mode: fast, full, console, or none "
                                  " (alert file alerts only)\n");
    FPUTS_UNIX ("                   \"unsock\" enables UNIX socket logging (experimental).\n");
    FPUTS_BOTH ("        -b         Log packets in tcpdump format (much faster!)\n");
    FPUTS_BOTH ("        -B <mask>  Obfuscated IP addresses in alerts and packet dumps using CIDR mask\n");
    FPUTS_BOTH ("        -c <rules> Use Rules File <rules>\n");
    FPUTS_BOTH ("        -C         Print out payloads with character data only (no hex)\n");
    FPUTS_BOTH ("        -d         Dump the Application Layer\n");
    FPUTS_UNIX ("        -D         Run Snort in background (daemon) mode\n");
    FPUTS_BOTH ("        -e         Display the second layer header info\n");
    FPUTS_WIN32("        -E         Log alert messages to NT Eventlog. (Win32 only)\n");
    FPUTS_BOTH ("        -f         Turn off fflush() calls after binary log writes\n");
    FPUTS_BOTH ("        -F <bpf>   Read BPF filters from file <bpf>\n");
    FPUTS_UNIX ("        -g <gname> Run snort gid as <gname> group (or gid) after initialization\n");
    FPUTS_BOTH ("        -G <0xid>  Log Identifier (to uniquely id events for multiple snorts)\n");
    FPUTS_BOTH ("        -h <hn>    Home network = <hn>\n");
    FPUTS_BOTH ("        -i <if>    Listen on interface <if>\n");
    FPUTS_BOTH ("        -I         Add Interface name to alert output\n");
#ifdef GIDS
#ifdef IPFW
    FPUTS_BOTH ("        -J <port>  ipfw divert socket <port> to listen on vice libpcap (FreeBSD only)\n");
#endif
#endif
    FPUTS_BOTH ("        -k <mode>  Checksum mode (all,noip,notcp,noudp,noicmp,none)\n");
    FPUTS_BOTH ("        -K <mode>  Logging mode (pcap[default],ascii,none)\n");
    FPUTS_BOTH ("        -l <ld>    Log to directory <ld>\n");
    FPUTS_BOTH ("        -L <file>  Log to this tcpdump file\n");
    FPUTS_UNIX ("        -M         Log messages to syslog (not alerts)\n");
    FPUTS_UNIX ("        -m <umask> Set umask = <umask>\n");
    FPUTS_BOTH ("        -n <cnt>   Exit after receiving <cnt> packets\n");
    FPUTS_BOTH ("        -N         Turn off logging (alerts still work)\n");
    FPUTS_BOTH ("        -o         Change the rule testing order to Pass|Alert|Log\n");
    FPUTS_BOTH ("        -O         Obfuscate the logged IP addresses\n");
    FPUTS_BOTH ("        -p         Disable promiscuous mode sniffing\n");
    fprintf(stdout, "        -P <snap>  Set explicit snaplen of packet (default: %d)\n",
                                    SNAPLEN);
    FPUTS_BOTH ("        -q         Quiet. Don't show banner and status report\n");
#ifdef GIDS
#ifndef IPFW
    FPUTS_BOTH ("        -Q         Use ip_queue for input vice libpcap (iptables only)\n");
#endif
#endif
    FPUTS_BOTH ("        -r <tf>    Read and process tcpdump file <tf>\n");
    FPUTS_BOTH ("        -R <id>    Include 'id' in snort_intf<id>.pid file name\n");
    FPUTS_BOTH ("        -s         Log alert messages to syslog\n");
    FPUTS_BOTH ("        -S <n=v>   Set rules file variable n equal to value v\n");
    FPUTS_UNIX ("        -t <dir>   Chroots process to <dir> after initialization\n");
    FPUTS_BOTH ("        -T         Test and report on the current Snort configuration\n");
    FPUTS_UNIX ("        -u <uname> Run snort uid as <uname> user (or uid) after initialization\n");
    FPUTS_BOTH ("        -U         Use UTC for timestamps\n");
    FPUTS_BOTH ("        -v         Be verbose\n");
    FPUTS_BOTH ("        -V         Show version number\n");
    FPUTS_WIN32("        -W         Lists available interfaces. (Win32 only)\n");
#ifdef DLT_IEEE802_11
    FPUTS_BOTH ("        -w         Dump 802.11 management and control frames\n");
#endif
    FPUTS_BOTH ("        -X         Dump the raw packet data starting at the link layer\n");
    FPUTS_BOTH ("        -y         Include year in timestamp in the alert and log files\n");
    FPUTS_BOTH ("        -Z <file>  Set the performonitor preprocessor file path and name\n");
    FPUTS_BOTH ("        -z         Set assurance mode, match on established sesions (for TCP)\n");
    FPUTS_BOTH ("        -?         Show this information\n");
    FPUTS_BOTH ("<Filter Options> are standard BPF options, as seen in TCPDump\n");

    FPUTS_BOTH ("Longname options and their corresponding single char version\n");
    FPUTS_BOTH ("   --logid <0xid>                  Same as -G\n");
    FPUTS_BOTH ("   --perfmon-file <file>           Same as -Z\n");
    FPUTS_BOTH ("   --pid-path <path>               Specify the path for the Snort PID file\n");
    FPUTS_BOTH ("   --snaplen <snap>                Same as -P\n");
    FPUTS_BOTH ("   --help                          Same as -?\n");
    FPUTS_BOTH ("   --alert-before-pass             Process alert, drop, sdrop, or reject before pass, default is pass before alert, drop,...\n");
    FPUTS_BOTH ("   --treat-drop-as-alert           Converts drop, sdrop, and reject rules into alert rules during startup\n");
    FPUTS_BOTH ("   --process-all-events            Process all queued events (drop, alert,...), default stops after 1st action group\n");
#ifdef DYNAMIC_PLUGIN
    FPUTS_BOTH ("   --dynamic-engine-lib <file>     Load a dynamic detection engine\n");
    FPUTS_BOTH ("   --dynamic-engine-lib-dir <path> Load all dynamic engines from directory\n");
    FPUTS_BOTH ("   --dynamic-detection-lib <file>  Load a dynamic rules library\n");
    FPUTS_BOTH ("   --dynamic-detection-lib-dir <path> Load all dynamic rules libraries from directory\n");
    FPUTS_BOTH ("   --dump-dynamic-rules <path>     Creates stub rule files of all loaded rules libraries\n");
    FPUTS_BOTH ("   --dynamic-preprocessor-lib <file>  Load a dynamic preprocessor library\n");
    FPUTS_BOTH ("   --dynamic-preprocessor-lib-dir <path> Load all dynamic preprocessor libraries from directory\n");
    FPUTS_BOTH ("   --dump-dynamic-preproc-genmsg <path>  Creates gen-msg.map files of all loaded preprocessor libraries\n");
#endif
    FPUTS_UNIX ("   --create-pidfile                Create PID file, even when not in Daemon mode\n");
    FPUTS_UNIX ("   --nolock-pidfile                Do not try to lock Snort PID file\n");
    FPUTS_UNIX ("   --disable-inline-initialization Do not perform the IPTables initialization in inline mode.\n");
#ifdef INLINE_FAILOPEN
    FPUTS_UNIX ("   --disable-inline-init-failopen  Do not fail open and pass packets while initializing with inline mode.\n");
#endif
#undef FPUTS_WIN32
#undef FPUTS_UNIX
#undef FPUTS_BOTH
    return 0;
}

void ParseDynamicLibInfo(int type)
{
#ifdef DYNAMIC_PLUGIN
    DynamicDetectionSpecifier *dynamicLib;
    char *tmpDir;
    switch (type)
    {
        case DYNAMIC_PREPROC_FILE: /* Load dynamic preprocessor lib specified */
        case DYNAMIC_PREPROC_DIRECTORY:
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Dynamic preprocessor specifier\n"););
            if (pv.dynamicPreprocCount >= MAX_DYNAMIC_PREPROC_LIBS)
            {
                FatalError("Maximum number of loaded Dynamic Preprocessor Libs (%d) exceeded\n", MAX_DYNAMIC_PREPROC_LIBS);
            }

            dynamicLib = (DynamicDetectionSpecifier *)SnortAlloc(sizeof(DynamicDetectionSpecifier));
            dynamicLib->type = type;
            if (!optarg && type == DYNAMIC_PREPROC_DIRECTORY)
            {
                tmpDir = getcwd(dynamicLib->path, 0);
                dynamicLib->path = strdup(tmpDir);

            } else if (optarg)
            {
                dynamicLib->path = strdup(optarg);
            }
            else
            {
                FatalError("Missing specifier for Dynamic Preprocessor Library\n");
            }
            pv.dynamicPreprocs[pv.dynamicPreprocCount] = dynamicLib;
            pv.dynamicPreprocCount++;
            break;
        case DYNAMIC_LIBRARY_FILE: /* Load dynamic detection lib specified */
        case DYNAMIC_LIBRARY_DIRECTORY:
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Dynamic detection specifier\n"););
            if (pv.dynamicLibraryCount >= MAX_DYNAMIC_PREPROC_LIBS)
            {
                FatalError("Maximum number of loaded Dynamic Detection Libs (%d) exceeded\n", MAX_DYNAMIC_PREPROC_LIBS);
            }

            dynamicLib = (DynamicDetectionSpecifier *)SnortAlloc(sizeof(DynamicDetectionSpecifier));
            dynamicLib->type = type;
            if (!optarg && type == DYNAMIC_LIBRARY_DIRECTORY)
            {
                tmpDir = getcwd(dynamicLib->path, 0);
                dynamicLib->path = strdup(tmpDir);
            }
            else if (optarg)
            {
                dynamicLib->path = strdup(optarg);
            }
            else
            {
                FatalError("Missing specifier for Dynamic Detection Library\n");
            }

            pv.dynamicDetection[pv.dynamicLibraryCount] = dynamicLib;
            pv.dynamicLibraryCount++;
            break;
        case DYNAMIC_ENGINE_FILE: /* Load dynamic engine lib specified */
        case DYNAMIC_ENGINE_DIRECTORY: /* Load dynamic engine lib specified */
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Dynamic engine specifier\n"););
            if (pv.dynamicEngineCount >= MAX_DYNAMIC_ENGINES)
            {
                FatalError("Maximum number of loaded Dynamic Engine Libs (%d) exceeded\n", MAX_DYNAMIC_ENGINES);
            }

            dynamicLib = (DynamicDetectionSpecifier *)SnortAlloc(sizeof(DynamicDetectionSpecifier));
            dynamicLib->type = type;

            if (!optarg && type == DYNAMIC_LIBRARY_DIRECTORY)
            {
                tmpDir = getcwd(dynamicLib->path, 0);
                dynamicLib->path = strdup(tmpDir);
            }
            else if (optarg)
            {
                dynamicLib->path = strdup(optarg);
            }
            else
            {
                FatalError("Missing specifier for Dynamic Engine Library\n");
            }

            pv.dynamicEngine[pv.dynamicEngineCount] = dynamicLib;
            pv.dynamicEngineCount++;
            break;
    }
#endif
}

/*
 * Function: ParseCmdLine(int, char *)
 *
 * Purpose:  Parse command line args
 *
 * Arguments: argc => count of arguments passed to the routine
 *            argv => 2-D character array, contains list of command line args
 *
 * Returns: 0 => success, 1 => exit on error
 */

#ifndef WIN32
#ifdef GIDS
#ifndef IPFW
static char *valid_options = "?a:A:bB:c:CdDefF:g:G:h:i:Ik:K:l:L:m:Mn:NoOpP:qQr:R:sS:t:Tu:UvVw:XyzZ:";
#else
static char *valid_options = "?a:A:bB:c:CdDefF:g:G:h:i:IJ:k:K:l:L:m:Mn:NoOpP:qr:R:sS:t:Tu:UvVw:XyzZ:";
#endif /* IPFW */
#else
    /* Unix does not support an argument to -s <wink marty!> OR -E, -W */
static char *valid_options = "?a:A:bB:c:CdDefF:g:G:h:i:Ik:K:l:L:m:Mn:NoOpP:qQr:R:sS:t:Tu:UvVw:XyzZ:";
#endif /* GIDS */
#else
    /* Win32 does not support:  -D, -g, -m, -t, -u */
    /* Win32 no longer supports an argument to -s, either! */
static char *valid_options = "?A:bB:c:CdeEfF:G:h:i:Ik:K:l:L:Mn:NoOpP:qr:R:sS:TUvVw:WXyzZ:";
#endif

#define LONGOPT_ARG_NONE 0
#define LONGOPT_ARG_REQUIRED 1
#define LONGOPT_ARG_OPTIONAL 2
static struct option long_options[] = {
   {"logid", LONGOPT_ARG_REQUIRED, NULL, 'G'},
   {"perfmon-file", LONGOPT_ARG_REQUIRED, NULL, 'Z'},
   {"snaplen", LONGOPT_ARG_REQUIRED, NULL, 'P'},
   {"help", LONGOPT_ARG_NONE, NULL, '?'},
#ifdef DYNAMIC_PLUGIN
   {"dynamic-engine-lib", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_ENGINE_FILE},
   {"dynamic-engine-lib-dir", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_ENGINE_DIRECTORY},
   {"dynamic-detection-lib", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_LIBRARY_FILE},
   {"dynamic-detection-lib-dir", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_LIBRARY_DIRECTORY},
   {"dump-dynamic-rules", LONGOPT_ARG_REQUIRED, NULL, DUMP_DYNAMIC_RULES},
   {"dynamic-preprocessor-lib", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_PREPROC_FILE},
   {"dynamic-preprocessor-lib-dir", LONGOPT_ARG_REQUIRED, NULL, DYNAMIC_PREPROC_DIRECTORY},
   {"dump-dynamic-preproc-genmsg", LONGOPT_ARG_REQUIRED, NULL, DUMP_DYNAMIC_PREPROCS},
#endif
   {"alert-before-pass", LONGOPT_ARG_NONE, NULL, ALERT_BEFORE_PASS},
   {"treat-drop-as-alert", LONGOPT_ARG_NONE, NULL, TREAT_DROP_AS_ALERT},
   {"process-all-events", LONGOPT_ARG_NONE, NULL, PROCESS_ALL_EVENTS},
   {"restart", LONGOPT_ARG_NONE, NULL, ARG_RESTART},
   {"pid-path", LONGOPT_ARG_REQUIRED, NULL, PID_PATH},
   {"create-pidfile", LONGOPT_ARG_NONE, NULL, CREATE_PID_FILE},
   {"nolock-pidfile", LONGOPT_ARG_NONE, NULL, NOLOCK_PID_FILE},
   {"disable-inline-initialization", LONGOPT_ARG_NONE, NULL, DISABLE_INLINE_INIT}, 
#ifdef INLINE_FAILOPEN
   {"disable-inline-init-failopen", LONGOPT_ARG_NONE, NULL, DISABLE_INLINE_FAILOPEN},
#endif
   {0, 0, 0, 0}
};

int ParseCmdLine(int argc, char *argv[])
{
    int ch;                         /* storage var for getopt info */
    int read_bpf = 0;
    char bpf_file[STD_BUF];
    char *eq_n;
    char *eq_p;
#ifdef WIN32
    char errorbuf[PCAP_ERRBUF_SIZE];
#endif
    int umaskchange = 1;
    int defumask = 0;
    int option_index = -1;
    int isName = 0;
#ifdef WIN32
    char *devicet;
    int adaplen;
#else
    int i;
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Parsing command line...\n"););
    /* generally speaking, Snort works best when it's in promiscuous mode */
    pv.promisc_flag = 1;

    /* just to be sane.. */
    username = NULL;
    groupname = NULL;
    pv.pidfile_suffix[0] = 0;

    pv.logtosyslog_flag = 0;
    
    /*
    **  Set this so we know whether to return 1 on invalid input.
    **  Snort uses '?' for help and getopt uses '?' for telling us there
    **  was an invalid option, so we can't use that to tell invalid input.
    **  Instead, we check optopt and it will tell us.
    */
    optopt = 0;

    /* loop through each command line var and process it */
    while((ch = getopt_long(argc, argv, valid_options, long_options, &option_index)) != -1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Processing cmd line switch: %c\n", ch););
        switch(ch)
        {
#ifdef DYNAMIC_PLUGIN
            case DYNAMIC_ENGINE_FILE: /* Load dynamic engine specified */
                ParseDynamicLibInfo(ch);
                break;
            case DYNAMIC_ENGINE_DIRECTORY: /* Load dynamic engine specified */
                ParseDynamicLibInfo(ch);
                break;
            case DYNAMIC_PREPROC_FILE: /* Load dynamic preprocessor lib specified */
                ParseDynamicLibInfo(ch);
                break;
            case DYNAMIC_PREPROC_DIRECTORY:
                ParseDynamicLibInfo(ch);
                break;
            case DYNAMIC_LIBRARY_FILE: /* Load dynamic detection lib specified */
                ParseDynamicLibInfo(ch);
                break;
            case DYNAMIC_LIBRARY_DIRECTORY:
                ParseDynamicLibInfo(ch);
                break;
            case DUMP_DYNAMIC_RULES:
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Dumping dynamic engine rules\n"););
                pv.dump_dynamic_rules_flag = 1;
                if (strlen(optarg) < STD_BUF)
                    SnortStrncpy(pv.dynamic_rules_path, optarg, STD_BUF);
                else
                    FatalError("Dump Path long than allowable %d characters\n", STD_BUF-1);
                break;
#endif
            case ALERT_BEFORE_PASS:
                pv.alert_before_pass=1;
                break;
            case PROCESS_ALL_EVENTS:
                pv.process_all_events=1;
                break;
            case TREAT_DROP_AS_ALERT:
                pv.treat_drop_as_alert=1;
                break;
            case PID_PATH:
                SnortStrncpy(pv.pid_path, optarg, STD_BUF);
                pv.create_pid_file = 1;
                break;
            case CREATE_PID_FILE:
                pv.create_pid_file = 1;
                break;
            case NOLOCK_PID_FILE:
                pv.nolock_pid_file = 1;
                break;
            case DISABLE_INLINE_INIT:
                pv.disable_inline_init_flag = 1;
                break;
#ifdef INLINE_FAILOPEN
            case DISABLE_INLINE_FAILOPEN:
                pv.inline_failopen_disabled_flag = 1;
                break;
#endif
            case 'A':                /* alert mode */
                if(!strcasecmp(optarg, "none"))
                {
                    pv.alert_mode = ALERT_NONE;
                }
                else if(!strcasecmp(optarg, "full"))
                {
                    pv.alert_mode = ALERT_FULL;
                }
                else if(!strcasecmp(optarg, "fast"))
                {
                    pv.alert_mode = ALERT_FAST;
                }
                else if(!strcasecmp(optarg, "console"))
                {
                    pv.alert_mode = ALERT_STDOUT;
                }
                else if(!strcasecmp(optarg, "cmg") ||
                        !strcasecmp(optarg, "jh") ||
                        !strcasecmp(optarg, "djr"))
                {
                    pv.alert_mode = ALERT_CMG;
                    /* turn off logging */
                    pv.log_mode = LOG_NONE;
                    pv.log_cmd_override = 1;
                    /* turn on layer2 headers */
                    pv.show2hdr_flag = 1;
                    /* turn on data dump */
                    pv.data_flag = 1;
                }
                else if(!strcasecmp(optarg, "unsock"))
                {
                    pv.alert_mode = ALERT_UNSOCK;
                }
                else
                {
                    FatalError("Unknown command line alert option: %s\n", optarg);
                }

                /* command line alert machanism has been specified, override 
                 * the config file options 
                 */ 
                pv.alert_cmd_override = 1;
                break;

            case 'b':                /* log packets in binary format for
                                      * post-processing */
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Tcpdump logging mode "
                            "active\n"););
                pv.log_mode = LOG_PCAP;
                pv.log_cmd_override = 1;
                break;

            case 'B': /* obfuscate with a substitution mask */
                pv.obfuscation_flag = 1;
                GenObfuscationMask(optarg);
                break;

            case 'c':                /* use configuration file x */
                if(!(pv.config_file = strdup(optarg)))
                    FatalError("Out of memory processing command line\n");
                break;

            case 'C':  /* dump the application layer as text only */
                pv.char_data_flag = 1;
                break;

            case 'd':                /* dump the application layer data */
                pv.data_flag = 1;
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Data Flag active\n"););
                break;

            case ARG_RESTART:        /* Restarting from daemon mode */
                pv.daemon_restart_flag = 1;
                /* Fall through */
            case 'D':                /* daemon mode */
#ifdef WIN32
                FatalError("Setting the Daemon mode is not supported in the "
                           "WIN32 port of snort!  Use 'snort /SERVICE ...' "
                           "instead\n");
#endif
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Daemon mode flag set\n"););
                pv.daemon_flag = 1;
                flow_set_daemon();
                pv.quiet_flag = 1;
                if (pv.test_mode_flag)
                {
                    FatalError("Cannot use test mode and daemon mode together."
                            "\nTo verify configuration run first in test "
                            "mode and then restart in daemon mode\n");
                }
                break;

            case 'e':                /* show second level header info */
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Show 2nd level active\n"););
                pv.show2hdr_flag = 1;
                break;

#ifdef WIN32
            case 'E':                /* log alerts to Event Log */
                pv.alert_mode = ALERT_SYSLOG;
                pv.syslog_remote_flag = 0;
                pv.alert_cmd_override = 1;
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Logging alerts to Event "
                            "Log\n"););
                break;
#endif
            case 'f':
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Pcap linebuffering "
                            "activated\n"););
                pv.line_buffer_flag = 1;
                break;

            case 'F':                /* read BPF filter in from a file */
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Tcpdump logging mode "
                            "active\n"););
                strlcpy(bpf_file, optarg, STD_BUF);
                read_bpf = 1;
                break;

            case 'g':                /* setgid handler */
#ifdef WIN32
                FatalError("Setting the group id is not supported in the WIN32 port of snort!\n");
#else
                if(groupname != NULL)
                    free(groupname);
                if((groupname = calloc(strlen(optarg) + 1, 1)) == NULL)
                    FatalPrintError("malloc");

                bcopy(optarg, groupname, strlen(optarg));

                isName = 0;
                for (i=0;i<strlen(groupname);i++)
                {
                    if (isdigit(groupname[i]) == 0)
                    {
                        isName = 1;
                        break;
                    }
                }
                if (((groupid = atoi(groupname)) == 0) || isName)
                {
                    gr = getgrnam(groupname);
                    if(gr == NULL)
                        FatalError("Group \"%s\" unknown\n", groupname);

                    groupid = gr->gr_gid;
                }
#endif
                break;

            case 'G':                /* snort loG identifier */
                if (!strncmp(optarg, "0x", 2))
                {
                    if (!sscanf(optarg, "0x%x", &pv.event_log_id))
                    {
                        pv.event_log_id = 0;
                    }
                }
                else
                {
                    char *endPtr;
                    pv.event_log_id = strtoul(optarg, &endPtr, 0);
                    if (endPtr == optarg)
                    {
                        FatalError("Snort log identifier invalid: %s\n",
                                optarg);
                    }
                }
                if (pv.event_log_id > 0xFFFF)
                {
                    FatalError("Snort log identifier invalid: %d.  It must "
                               "be no larger than a 2 byte value\n",
                               pv.event_log_id);
                }
                else
                {
                    u_int32_t id = pv.event_log_id;
                    pv.event_log_id = id << 16;
                }
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Log ID: 0x%x\n", pv.event_log_id););
                break;

            case 'h':                /* set home network to x, this will help
                                      * determine what to set logging diectories
                                      * to */
                GenHomenet(optarg);
                break;

            case 'i':
                if(pv.interface)
                {
                    FatalError("Cannot specify more than one network "
                               "interface on the command line.\n");
                }
#ifdef WIN32
                /* first, try to handle the "-i1" case, where an interface
                 * is specified by number.  If this fails, then fall-through
                 * to the case outside the ifdef/endif, where an interface
                 * can be specified by its fully qualified name, like as is
                 * shown by running 'snort -W', ie.
                 * "\Device\Packet_{12345678-90AB-CDEF-1234567890AB}"
                 */
                devicet = NULL;
                adaplen = atoi(optarg);
                if( adaplen > 0 )
                {
                    devicet = pcap_lookupdev(errorbuf);
                    if ( devicet == NULL )
                    {
                        perror(errorbuf);
                        exit(1);
                    }

                    pv.interface = GetAdapterFromList(devicet, adaplen);
                    if ( pv.interface == NULL )
                    {
                        LogMessage("Invalid interface '%d'.\n", atoi(optarg));
                        exit(1);
                    }


                    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Interface = %s\n",
                                PRINT_INTERFACE(pv.interface)));
                }
                else
#endif  /* WIN32 */
                /* this code handles the case in which the user specifies
                   the entire name of the interface and it is compiled
                   regardless of which OS you have */
                {
                    pv.interface = (char *)SnortAlloc(strlen(optarg) + 1);
                    strlcpy(pv.interface, optarg, strlen(optarg)+1);
                    DEBUG_WRAP(DebugMessage(DEBUG_INIT,
                        "Interface = %s\n",
                        PRINT_INTERFACE(pv.interface)););
                }
                break;

            case 'I':       /* add interface name to alert string */
                pv.alert_interface_flag = 1;
                break;

#ifdef GIDS
#ifdef IPFW
            case 'J':
                LogMessage("Reading from ipfw divert socket\n");
                pv.inline_flag = 1;
                pv.divert_port = atoi(optarg);
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Divert port set to: %d\n", pv.divert_port););
                LogMessage("IPFW Divert port set to: %d\n", pv.divert_port);
                pv.promisc_flag = 0;
                pv.interface = NULL;
                break;
#endif
#endif


            case 'k':  /* set checksum mode */
                if(!strcasecmp(optarg, "all"))
                {
                    pv.checksums_mode = DO_IP_CHECKSUMS | DO_TCP_CHECKSUMS |
                                        DO_UDP_CHECKSUMS | DO_ICMP_CHECKSUMS;
                }
                else if(!strcasecmp(optarg, "noip")) 
                {
                    pv.checksums_mode ^= DO_IP_CHECKSUMS;
                }
                else if(!strcasecmp(optarg, "notcp"))
                {
                    pv.checksums_mode ^= DO_TCP_CHECKSUMS;
                }
                else if(!strcasecmp(optarg, "noudp"))
                {
                    pv.checksums_mode ^= DO_UDP_CHECKSUMS;
                }
                else if(!strcasecmp(optarg, "noicmp"))
                {
                    pv.checksums_mode ^= DO_ICMP_CHECKSUMS;
                }
                if(!strcasecmp(optarg, "none"))
                {
                    pv.checksums_mode = 0;
                }
                break;

            case 'K':                /* log mode */
                if(!strcasecmp(optarg, "none"))
                {
                    pv.log_mode = LOG_NONE;
                    pv.log_cmd_override = 1;
                }
                else if(!strcasecmp(optarg, "pcap"))
                {
                    pv.log_mode = LOG_PCAP;
                    pv.log_cmd_override = 1;
                }
                else if(!strcasecmp(optarg, "ascii"))
                {
                    pv.log_mode = LOG_ASCII;
                    pv.log_cmd_override = 1;
                }
                else
                {
                    FatalError("Unknown command line log option: %s\n", optarg);
                }
                break;

            case 'l':                /* use log dir <X> */
                if(!(pv.log_dir = strdup(optarg)))
                {
                    FatalError("Out of memory processing command line\n");
                }

                if(access(pv.log_dir, 2) != 0)
                {
                    FatalError("log directory '%s' does not exist\n", 
                            pv.log_dir);
                }
                break;

            case 'L':  /* set BinLogFile name */
                /* implies tcpdump format logging */
                if (strlen(optarg) < 256)
                {
                    pv.log_mode = LOG_PCAP;
                    pv.binLogFile = strdup(optarg);
                    pv.log_cmd_override = 1;
                }
                else
                {
                    FatalError("ParseCmdLine, log file: %s, > than 256 characters\n",
                               optarg);
                }             
                break;

            case 'M':
                pv.logtosyslog_flag = 1;
                break;
                
            case 'm': /* set the umask for the output files */
#ifdef WIN32
                FatalError("Setting the umask is not supported in the "
                           "WIN32 port of snort!\n");
#endif
                {
                    char *p;
                    long val = 0;

                    umaskchange = 0;

                    val = strtol(optarg, &p, 8);
                    if (*p != '\0' || val < 0 || (val & ~FILEACCESSBITS))
                    {
                        FatalError("bad umask %s\n", optarg);
                    }
                    else
                    {
                        defumask = val;
                    }
                }
                break;

            case 'n':                /* grab x packets and exit */
                pv.pkt_cnt = atoi(optarg);
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Exiting after %d packets\n", pv.pkt_cnt););
                break;

            case 'N':                /* no logging mode */
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Logging deactivated\n"););
                pv.log_mode = LOG_NONE;
                pv.log_cmd_override = 1;
                break;

            case 'o': /* change the rules processing order to
                       * passlist first */
                /* depracated  pv.rules_order_flag = 1;  see alert-before-pass */
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Rule application order changed to Pass->Alert->Log (DEPRACATED!!!)\n"););
                break;

            case 'O':  /* obfuscate the logged IP addresses for
                        * privacy */
                pv.obfuscation_flag = 1;
                break;

            case 'p':  /* disable explicit promiscuous mode */
                pv.promisc_flag = 0;
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Promiscuous mode disabled!\n"););
                break;

            case 'P':  /* explicitly define snaplength of packets */
                pv.pkt_snaplen = atoi(optarg);
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Snaplength of Packets set to: %d\n", pv.pkt_snaplen););
                break;

            case 'q':  /* no stdout output mode */
                pv.quiet_flag = 1;
                break;

            case 'Q':
                LogMessage("Reading from iptables\n");
                pv.inline_flag = 1;
                break;

            case 'r':  /* read packets from a TCPdump file instead
                        * of the net */
                strlcpy(pv.readfile, optarg, STD_BUF);
                pv.readmode_flag = 1;
                if(argc == 3)
                {
                    LogMessage("No run mode specified, defaulting to verbose mode\n");
                    pv.verbose_flag = 1;
                    pv.data_flag = 1;
                }
                break;

            case 'R': /* augment pid file name CPW*/
                if (strlen(optarg) < MAX_PIDFILE_SUFFIX && strlen(optarg) > 0)
                {
                    if (!strstr(optarg, "..") && !(strstr(optarg, "/")))
                    {
                        snprintf(pv.pidfile_suffix, MAX_PIDFILE_SUFFIX, "%s",
                                optarg);
                    }
                    else
                    {
                        FatalError("ERROR: illegal pidfile suffix: %s\n",
                                optarg);
                    }
                }
                else
                {
                    FatalError("ERROR: pidfile suffix length problem: %d\n",
                            strlen(optarg) );
                }
                break;

            case 's':  /* log alerts to syslog */
                pv.alert_mode = ALERT_SYSLOG;
#ifndef WIN32
                /* command line alerting option has been specified, 
                 * override the alert options in the config file
                 */ 
                pv.alert_cmd_override = 1;
#else
                pv.alert_cmd_override = 0;
                pv.syslog_remote_flag = 1;
#endif
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Logging alerts to "
                            "syslog\n"););
                break;

            case 'S':  /* set a rules file variable */
                if((eq_p = strchr(optarg, '=')) != NULL)
                {
                    struct VarEntry *p;
                    int namesize = eq_p-optarg;
                    eq_n = (char *)SnortAlloc((namesize + 2) * sizeof(char));
                    strlcpy(eq_n, optarg, namesize+1);
                    p = VarDefine(eq_n, eq_p + 1);
                    p->flags |= VAR_STATIC;
                    free(eq_n);
                }
                else
                {
                    FatalError("Format for command line variable definitions "
                               "is:\n -S var=value\n");
                }
                break;

            case 't':  /* chroot to the user specified directory */
#ifdef WIN32
                FatalError("Setting the chroot directory is not supported in "
                           "the WIN32 port of snort!\n");
#endif  /* WIN32 */
                if(!(pv.chroot_dir = strdup(optarg)))
                    FatalError("Out of memory processing command line\n");
                break;

            case 'T': /* test mode, verify that the rules load properly */
                pv.test_mode_flag = 1;
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Snort starting in test mode...\n"););
                if (pv.daemon_flag)
                {
                    FatalError("Cannot use test mode and daemon mode together."
                            "\nTo verify configuration run first in test "
                            "mode and then restart in daemon mode\n");
                }
                break;    

            case 'u':  /* setuid */
#ifdef WIN32
                FatalError("Setting the user id is not "
                           "supported in the WIN32 port of snort!\n");
#else
                if((username = calloc(strlen(optarg) + 1, 1)) == NULL)
                    FatalPrintError("malloc");

                bcopy(optarg, username, strlen(optarg));

                isName = 0;
                for (i=0;i<strlen(username);i++)
                {
                    if (isdigit(username[i]) == 0)
                    {
                        isName = 1;
                        break;
                    }
                }

                if (((userid = atoi(username)) == 0) || isName)
                {
                    pw = getpwnam(username);
                    if(pw == NULL)
                        FatalError("User \"%s\" unknown\n", username);

                    userid = pw->pw_uid;
                }
                else
                {
                    pw = getpwuid(userid);
                    if(pw == NULL)
                        FatalError(
                                "Can not obtain username for uid: %lu\n",
                                (u_long) userid);
                }

                if(groupname == NULL)
                {
                    char name[256];

                    snprintf(name, 255, "%lu", (u_long) pw->pw_gid);

                    if((groupname = calloc(strlen(name) + 1, 1)) == NULL)
                    {
                        FatalPrintError("malloc");
                    }
                    groupid = pw->pw_gid;
                }
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "UserID: %lu GroupID: %lu\n",
                    (unsigned long) userid, (unsigned long) groupid););
#endif  /* !WIN32 */
                break;

            case 'U': /* use UTC */
                pv.use_utc = 1;
                break;

            case 'v': /* be verbose */
                pv.verbose_flag = 1;
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Verbose Flag active\n"););
                break;

            case 'V': /* prog ver already gets printed out, so we
                       * just exit */
                pv.print_version = ch;
                pv.quiet_flag = 1;
                break;

#ifdef WIN32
            case 'W':
                if ((pv.interface = pcap_lookupdev(errorbuf)) == NULL)
                    perror(errorbuf);

                pv.print_version = ch;
                pv.quiet_flag = 1;
                break;
#endif  /* WIN32 */

#ifdef DLT_IEEE802_11
            case 'w':                /* show 802.11 all frames info */
                pv.showwifimgmt_flag = 1;
                break;
#endif

            case 'X':  /* display verbose packet bytecode dumps */
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Verbose packet bytecode dumps enabled\n"););
                pv.verbose_bytedump_flag = 1;
                break;

            case 'y':  /* Add year to timestamp in alert and log files */
                pv.include_year = 1;
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Enabled year in timestamp\n"););
                break;

            case 'Z': /* Set preprocessor performon file path/filename */
                SetPerfmonitorFile(optarg);
                break;

            case '?':  /* show help and exit with 1 */
                pv.print_version = ch;
                pv.quiet_flag = 1;
        }
    }

    /* TODO relocate all of this to later in startup process */

    /* if the umask arg happened, set umask */
    if (umaskchange)
    {
        umask(077);           /* set default to be sane */
    }
    else
    {
        umask(defumask);
    }

    /* if we're reading in BPF filters from a file */
    if(read_bpf)
    {
        /* suck 'em in */
        pv.pcap_cmd = read_infile(bpf_file);
    }
    else
    {
        /* set the BPF rules string (thanks Mike!) */
        pv.pcap_cmd = copy_argv(&argv[optind]);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "pcap_cmd is %s\n", 
                pv.pcap_cmd !=NULL ? pv.pcap_cmd : "NULL"););
    return 0;
}

/*
 * Function: SetPktProcessor()
 *
 * Purpose:  Set which packet processing function we're going to use based on
 *           what type of datalink layer we're using
 *
 * Arguments: int num => number of interface
 *
 * Returns: 0 => success
 */
int SetPktProcessor()
{
#ifdef GIDS
    if (InlineMode())
    {

#ifndef IPFW
        if(!pv.quiet_flag)
            LogMessage("Setting the Packet Processor to decode packets "
                    "from iptables\n");

        grinder = DecodeIptablesPkt;
#else
        if(!pv.quiet_flag)
            LogMessage("Setting the Packet Processor to decode packets "
                    "from ipfw divert\n");

        grinder = DecodeIpfwPkt;
#endif /* IPFW */

        return 0;

    }
#endif /* GIDS */

    switch(datalink)
    {
        case DLT_EN10MB:        /* Ethernet */
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding Ethernet on interface %s\n", 
                            PRINT_INTERFACE(pv.interface));
            }

            grinder = DecodeEthPkt;
            break;

#ifdef DLT_IEEE802_11
        case DLT_IEEE802_11:
            if (!pv.readmode_flag)
            {
                if (!pv.quiet_flag)
                    LogMessage("Decoding IEEE 802.11 on interface %s\n",
                            PRINT_INTERFACE(pv.interface));
            }

            grinder = DecodeIEEE80211Pkt;
            break;
#endif
#ifdef DLT_ENC
        case DLT_ENC:           /* Encapsulated data */
            if (!pv.readmode_flag)
            {
                if (!pv.quiet_flag)
                    LogMessage("Decoding Encapsulated data on interface %s\n",
                           PRINT_INTERFACE(pv.interface));
            }

            grinder = DecodeEncPkt;
            break;

#else
        case 13:
#endif /* DLT_ENC */
#ifdef DLT_IEEE802
        case DLT_IEEE802:                /* Token Ring */
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding Token Ring on interface %s\n", 
                            PRINT_INTERFACE(pv.interface));
            }

            grinder = DecodeTRPkt;

            break;
#endif

#ifdef DLT_FDDI
        case DLT_FDDI:                /* FDDI */
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding FDDI on interface %s\n", 
                            PRINT_INTERFACE(pv.interface));
            }

            grinder = DecodeFDDIPkt;

            break;
#endif

#ifdef DLT_CHDLC
        case DLT_CHDLC:              /* Cisco HDLC */
            if (!pv.readmode_flag && !pv.quiet_flag)
                LogMessage("Decoding Cisco HDLC on interface %s\n", 
                        PRINT_INTERFACE(pv.interface));

            grinder = DecodeChdlcPkt;

            break;
#endif

#ifdef DLT_SLIP
        case DLT_SLIP:                /* Serial Line Internet Protocol */
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding Slip on interface %s\n", 
                            PRINT_INTERFACE(pv.interface));
            }

            if(pv.show2hdr_flag == 1)
            {
                LogMessage("Second layer header parsing for this datalink "
                        "isn't implemented yet\n");

                pv.show2hdr_flag = 0;
            }

            grinder = DecodeSlipPkt;

            break;
#endif

#ifdef DLT_PPP
        case DLT_PPP:                /* point-to-point protocol */
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding PPP on interface %s\n", 
                            PRINT_INTERFACE(pv.interface));
            }

            if(pv.show2hdr_flag == 1)
            {
                /* do we need ppp header showup? it's only 4 bytes anyway ;-) */
                LogMessage("Second layer header parsing for this datalink "
                        "isn't implemented yet\n");
                pv.show2hdr_flag = 0;
            }

            grinder = DecodePppPkt;

            break;
#endif

#ifdef DLT_PPP_SERIAL
        case DLT_PPP_SERIAL:         /* PPP with full HDLC header*/
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding PPP on interface %s\n", 
                            PRINT_INTERFACE(pv.interface));
            }

            if(pv.show2hdr_flag == 1)
            {
                /* do we need ppp header showup? it's only 4 bytes anyway ;-) */
                LogMessage("Second layer header parsing for this datalink "
                        "isn't implemented yet\n");
                pv.show2hdr_flag = 0;
            }

            grinder = DecodePppSerialPkt;

            break;
#endif

#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding 'ANY' on interface %s\n", 
                            PRINT_INTERFACE(pv.interface));
            }

            grinder = DecodeLinuxSLLPkt;

            break;
#endif

#ifdef DLT_PFLOG
        case DLT_PFLOG:
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding OpenBSD PF log on interface %s\n",
                            PRINT_INTERFACE(pv.interface));
            }

            grinder = DecodePflog;

            break;
#endif

#ifdef DLT_OLDPFLOG
        case DLT_OLDPFLOG:
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding old OpenBSD PF log on interface %s\n",
                            PRINT_INTERFACE(pv.interface));
            }

            grinder = DecodeOldPflog;

            break;
#endif

#ifdef DLT_LOOP
        case DLT_LOOP:
#endif
#ifdef DLT_NULL
        case DLT_NULL:            /* loopback and stuff.. you wouldn't perform
                                   * intrusion detection on it, but it's ok for
                                   * testing. */
#endif
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                {
                    LogMessage("Decoding LoopBack on interface %s\n", 
                            PRINT_INTERFACE(pv.interface));
                }
            }

            if(pv.show2hdr_flag == 1)
            {
                LogMessage("Data link layer header parsing for this network "
                        " type isn't implemented yet\n");
                pv.show2hdr_flag = 0;
            }
            grinder = DecodeNullPkt;

            break;

#ifdef DLT_RAW /* Not supported in some arch or older pcap
                * versions */
        case DLT_RAW:
            if(!pv.readmode_flag)
            {
                if(!pv.quiet_flag)
                    LogMessage("Decoding raw data on interface %s\n", 
                            PRINT_INTERFACE(pv.interface));
            }

            if(pv.show2hdr_flag == 1)
            {
                LogMessage("There's no second layer header available for "
                        "this datalink\n");
                pv.show2hdr_flag = 0;
            }
            grinder = DecodeRawPkt;

            break;
#endif
            /*
             * you need the I4L modified version of libpcap to get this stuff
             * working
             */
#ifdef DLT_I4L_RAWIP
        case DLT_I4L_RAWIP:
            if (! pv.readmode_flag && !pv.quiet_flag)
                LogMessage("Decoding I4L-rawip on interface %s\n", 
                        PRINT_INTERFACE(pv.interface));

            grinder = DecodeI4LRawIPPkt;

            break;
#endif

#ifdef DLT_I4L_IP
        case DLT_I4L_IP:
            if (! pv.readmode_flag && !pv.quiet_flag)
                LogMessage("Decoding I4L-ip on interface %s\n", 
                        PRINT_INTERFACE(pv.interface));

            grinder = DecodeEthPkt;

            break;
#endif

#ifdef DLT_I4L_CISCOHDLC
        case DLT_I4L_CISCOHDLC:
            if (! pv.readmode_flag && !pv.quiet_flag)
                LogMessage("Decoding I4L-cisco-h on interface %s\n", 
                        PRINT_INTERFACE(pv.interface));

            grinder = DecodeI4LCiscoIPPkt;

            break;
#endif

        default:                        /* oops, don't know how to handle this one */
            ErrorMessage("\n%s cannot handle data link type %d\n",
                    progname, datalink);
            CleanExit(1);
    }

    return 0;
}
/*
 *  Handle idle time checks in snort packet processing loop 
 */
static 
int snort_idle()
{
    /* Rollover of performance log */ 
    if( pv.rotate_perf_file )
    {
        sfRotatePerformanceStatisticsFile(&sfPerf);
        pv.rotate_perf_file=0; 
    }
    
    return 0;
}

#ifdef INLINE_FAILOPEN
void PcapIgnorePacket(char *user, struct pcap_pkthdr * pkthdr, u_char * pkt)
{
    DEBUG_WRAP(FILE *tmp;);

    /* Empty function -- do nothing with the packet we just read */
    pv.pass_thread_pktcount++;

    DEBUG_WRAP(
            tmp = fopen("/var/tmp/fo_threadid", "a");
            fprintf(tmp, "Packet Count %d\n", pv.pass_thread_pktcount);
            fclose(tmp);
            );

    return;
}

void *InlinePatternMatcherInitThread(void *arg)
{
    sigset_t mtmask, oldmask;
    DEBUG_WRAP(FILE *tmp;);

    sigemptyset(&mtmask);

    pv.pass_thread_pid = getpid();

    DEBUG_WRAP(
            tmp = fopen("/var/tmp/fo_threadid", "w");
            fprintf(tmp, "Fail Open Thread ID: %d\n", pv.pass_thread_pid);
            fclose(tmp);
            );

    /* Get the current set of signals inherited from main thread. */
    pthread_sigmask(SIG_UNBLOCK, &mtmask, &oldmask);

    /* Now block those signals from being delivered to this thread.
     * now Main receives all signals. */
    pthread_sigmask(SIG_BLOCK, &oldmask, NULL);

    /* Now block those signals from being delivered to this thread.
     * now Main receives all signals. */
    pthread_sigmask(SIG_BLOCK, &oldmask, NULL);

    pv.pass_thread_running_flag = 1;

    /* simple mutexy wait for main thread to stop printing stuff... */
    while (!pv.initialization_done_flag)
    {
        sleep(1);
    }

    /* Do the fast packet initialization */
    fpCreateFastPacketDetection();

    pv.pass_thread_running_flag = 0;

    pthread_exit(NULL);

    return NULL;
}
#endif
    
/*
 * Function: void *InterfaceThread(void *arg)
 *
 * Purpose: wrapper for pthread_create() to create a thread per interface
 */
static struct timeval starttime;
static struct timeval endtime;
void *InterfaceThread(void *arg)
{
    int pcap_ret;
    struct timezone tz;
    int pkts_to_read = pv.pkt_cnt;

    bzero((char *) &tz, sizeof(tz));
    gettimeofday(&starttime, &tz);

    signal_location =  SIGLOC_PCAP_LOOP;

    /* Read all packets on the device.  Continue until cnt packets read */
#ifdef USE_PCAP_LOOP
    pcap_ret = pcap_loop(pd, pv.pkt_cnt, (pcap_handler) PcapProcessPacket, NULL);
#else
    while(1)
    {
        pcap_ret = pcap_dispatch(pd, pkts_to_read, (pcap_handler)PcapProcessPacket, NULL);
        if (pv.usr_signal == SIGHUP)
        {
            pv.done_processing = 1;
            return NULL;
        }

        if (pcap_ret < 0)
        {
            break;
        }

        /* If reading from a file... 0 packets at EOF */
        if (pv.readmode_flag && (pcap_ret == 0))
        {
            break;
        }

        /* continue... pcap_ret packets that time around. */
        pkts_to_read -= pcap_ret;

        if ((pkts_to_read <= 0) && (pv.pkt_cnt != -1))
        {
            break;
        }
      
        /* check for signals */
        if (sig_check())
        {
            if (hup_check())
            {
                /* Actually return so we can restart */
                return NULL;
            }
        }

        /* idle time processing..quick things to check or do ... */
        snort_idle();
    }
#endif
    if (pcap_ret < 0)
    {
        if(pv.daemon_flag)
        {
            syslog(LOG_PID | LOG_CONS | LOG_DAEMON,
                    "pcap_loop: %s", pcap_geterr(pd));
        }
        else
        {
            ErrorMessage("pcap_loop: %s\n", pcap_geterr(pd));
        }
        CleanExit(1);
    }
    
    signal_location =  0;

    pv.done_processing = 1;

    CleanExit(0);

    return NULL;                /* avoid warnings */
}



/****************************************************************************
 *
 * Function: OpenPcap(char *, int)
 *
 * Purpose:  Open the libpcap interface
 *
 * Arguments: intf => name of the interface to open
 *            num  => number of the interface (to fill-in datalink and pd)
 *
 * Returns: 0 => success, exits on problems
 *
 ****************************************************************************/
int OpenPcap()
{
    bpf_u_int32 localnet, netmask;        /* net addr holders */
    struct bpf_program fcode;        /* Finite state machine holder */
    char errorbuf[PCAP_ERRBUF_SIZE];        /* buffer to put error strings in */
    bpf_u_int32 defaultnet = 0xFFFFFF00;

    errorbuf[0] = '\0';

    /* if we're not reading packets from a file */
    if(pv.interface == NULL)
    {
        if (!pv.readmode_flag)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_INIT,
                    "pv.interface is NULL, looking up interface....   "););
            /* look up the device and get the handle */
            pv.interface = pcap_lookupdev(errorbuf);
    
            DEBUG_WRAP(DebugMessage(DEBUG_INIT,
                    "found interface %s\n", PRINT_INTERFACE(pv.interface)););
            /* uh oh, we couldn't find the interface name */
            if(pv.interface == NULL)
            {
                FatalError("OpenPcap() interface lookup: \n\t%s\n",
               errorbuf);
            }
        }
        else
        {
            /* interface is null and we are in readmode */
            /* some routines would hate it to be NULL */
            pv.interface = "[reading from a file]"; 
        }
    }

    if(!pv.quiet_flag)
    {
        if (!pv.readmode_flag)
            LogMessage("\nInitializing Network Interface %s\n", 
                    PRINT_INTERFACE(pv.interface));
        else 
            LogMessage("TCPDUMP file reading mode.\n");
    }

    if (!pv.readmode_flag)
    {
        if(pv.pkt_snaplen)        /* if it's set let's try it... */
        {
            if(pv.pkt_snaplen < MIN_SNAPLEN)        /* if it's < MIN set it to
                                                     * MIN */
            {
                /* XXX: Warning message, specidifed snaplen too small,
                 * snaplen set to X
                 */
                 snaplen = MIN_SNAPLEN;
            }
            else
            {
                 snaplen = pv.pkt_snaplen;
            }
         }
         else
         {
             snaplen = SNAPLEN;        /* otherwise let's put the compiled value in */
         }
        
        DEBUG_WRAP(DebugMessage(DEBUG_INIT,
                "snaplength info: set=%d/compiled=%d/wanted=%d\n",
                snaplen,  SNAPLEN, pv.pkt_snaplen););
    
        /* get the device file descriptor */
        pd = pcap_open_live(pv.interface, snaplen,
                pv.promisc_flag ? PROMISC : 0, READ_TIMEOUT, errorbuf);

    }
    else
    {   /* reading packets from a file */

        if (!pv.quiet_flag)
        {
            LogMessage("Reading network traffic from \"%s\" file.\n", 
                    pv.readfile);
        }
        /* open the file */
        pd = pcap_open_offline(pv.readfile, errorbuf);

        /* the file didn't open correctly */
        if(pd == NULL)
        {
            FatalError("unable to open file \"%s\" for readback: %s\n",
                       pv.readfile, errorbuf);
        }
        /*
         * set the snaplen for the file (so we don't get a lot of extra crap
         * in the end of packets
         */
        snaplen = pcap_snapshot(pd);

        if(!pv.quiet_flag)
            LogMessage("snaplen = %d\n", snaplen);
    }

    /* something is wrong with the opened packet socket */
    if(pd == NULL)
    {
        if(strstr(errorbuf, "Permission denied"))
        {
            FatalError("You don't have permission to"
                       " sniff.\nTry doing this as root.\n");
        }
        else
        {
            FatalError("OpenPcap() device %s open: \n\t%s\n",
                       PRINT_INTERFACE(pv.interface), errorbuf);
        }
    }

    if (strlen(errorbuf) > 0)
    {
        LogMessage("Warning: OpenPcap() device %s success with warning:"
                   "\n\t%s\n", PRINT_INTERFACE(pv.interface), errorbuf);
    }

    /* get local net and netmask */
    if(pcap_lookupnet(pv.interface, &localnet, &netmask, errorbuf) < 0)
    {
       if (!pv.readmode_flag)
       {
           ErrorMessage("OpenPcap() device %s network lookup: \n"
                        "\t%s\n",
                        PRINT_INTERFACE(pv.interface), errorbuf);

       }
        /*
         * set the default netmask to 255.255.255.0 (for stealthed
         * interfaces)
         */
        netmask = htonl(defaultnet);
    }

    /* compile BPF filter spec info fcode FSM */
    if(pcap_compile(pd, &fcode, pv.pcap_cmd, 1, netmask) < 0)
    {
        FatalError("OpenPcap() FSM compilation failed: \n\t%s\n"
                   "PCAP command: %s\n", pcap_geterr(pd), pv.pcap_cmd);
    }
    /* set the pcap filter */
    if(pcap_setfilter(pd, &fcode) < 0)
    {
        FatalError("OpenPcap() setfilter: \n\t%s\n",
                   pcap_geterr(pd));
    }
    
    /* get data link type */
    datalink = pcap_datalink(pd);

    if(datalink < 0)
    {
        FatalError("OpenPcap() datalink grab: \n\t%s\n",
                   pcap_geterr(pd));
    }
    return 0;
}



/* locate one of the possible default config files */
/* allocates memory to hold filename */
static char *ConfigFileSearch()
{
    struct stat st;
    int i;
    char *conf_files[]={"/etc/snort.conf", "./snort.conf", NULL};
    char *fname = NULL;
    char *rval = NULL;

    i = 0;

    /* search the default set of config files */
    while(conf_files[i])
    {
        fname = conf_files[i];

        if(stat(fname, &st) != -1)
        {
            if(!(rval = strdup(fname)))
                FatalError("Out of memory searching for config file\n");
            break;
        }
        i++;
    }

    /* search for .snortrc in the HOMEDIR */
    if(!rval)
    {
        char *home_dir = NULL;

        if((home_dir = getenv("HOME")) != NULL)
        {
            char *snortrc = "/.snortrc";
            int path_len;

            path_len = strlen(home_dir) + strlen(snortrc) + 1;

            /* create the full path */
            fname = (char *)SnortAlloc(path_len);

            snprintf(fname, path_len, "%s%s", home_dir, snortrc);

            if(stat(fname, &st) != -1)
                rval = fname;
            else
                free(fname);
        }
    }

    return rval;
}

static int ProcessAlertCommandLine()
{
    
    if(!pv.alert_cmd_override)
    {
        /* Setup the default output plugin */
        ActivateOutputPlugin("alert_full", NULL);
    }
    else
    {
        switch(pv.alert_mode)
        {
            case ALERT_FAST:
                ActivateOutputPlugin("alert_fast", NULL);
                break;

            case ALERT_FULL:
                ActivateOutputPlugin("alert_full", NULL);
                break;

            case ALERT_NONE:
                SetOutputList(NoAlert, NT_OUTPUT_ALERT, NULL);
                break;

            case ALERT_UNSOCK:
                ActivateOutputPlugin("alert_unixsock", NULL);
                break;

            case ALERT_STDOUT:
                ActivateOutputPlugin("alert_fast", "stdout");
                break;

            case ALERT_CMG:
                ActivateOutputPlugin("alert_fast", "stdout packet");
                break;

            case ALERT_SYSLOG:
                ActivateOutputPlugin("alert_syslog", NULL);
                break;

            default:
                FatalError("Unknown alert mode %u\n", pv.alert_mode);
                break;
        }
    }

    return 0;
}

static int ProcessLogCommandLine()
{
    if(!pv.log_cmd_override)
    {
        ActivateOutputPlugin("log_tcpdump", NULL);
    }
    else
    {
        switch(pv.log_mode)
        {
            case LOG_ASCII:
                ActivateOutputPlugin("log_ascii", NULL);
                break;
                
            case LOG_PCAP:
                if(pv.binLogFile)
                    ActivateOutputPlugin("log_tcpdump", pv.binLogFile);
                else
                    ActivateOutputPlugin("log_tcpdump", NULL);
                break;
                
            case LOG_NONE:
                SetOutputList(NoLog, NT_OUTPUT_LOG, NULL);
                break;
                
            default:
                FatalError("Unknown log mode %u\n", pv.log_mode);
        }
    }

    return 0;
}

/* Signal Handlers ************************************************************/
void saveSignalInfo(int signal)
{
    /* If we are already processing an exit signal, nothing to do */
    if (pv.exit_signal)
        return;

    pv.exit_signal = signal;
}

#ifdef CATCH_SEGV
static int sawSegv = 0;
static void SigSegvHandler(int signal)
{
    if (sawSegv == 1)
    {
        /* Handle the reentrant issues for SEGV...
         * If we get a SEGV while processing one, just exit */
        exit(-1);
    }

    sawSegv = 1;
    saveSignalInfo(signal);
    LogMessage("*** \n");
    LogMessage("*** Snort caught a SEGV exception, shutting down.\n");

    switch( signal_location)
    {
        case SIGLOC_PARSE_RULES_FILE:
            LogMessage("*** SEGV caught while parsing '%s' at line %d.\n",
                       file_name, file_line );
            break;

        case SIGLOC_PCAP_LOOP:
            if( current_otn )
            {
                LogMessage("*** SEGV caught in event generator id = %u, sid = %u\n",
                           current_otn->sigInfo.generator, current_otn->sigInfo.id);
            }
            break;

        default:
            break;
    }

    LogMessage("*** \n");

    CleanExit(1);
}
#endif

static void SigTermHandler(int signal)
{
    saveSignalInfo(signal);
}

static void SigIntHandler(int signal)
{
    saveSignalInfo(signal);
}   

static void SigQuitHandler(int signal)
{
    saveSignalInfo(signal);
}

static void SigHupHandler(int signal)
{
    pv.usr_signal = signal;
}

/**
 * dummy signal handler for nonroot users or chroot.
 *
 * @param signal signal to exec
 */
void SigCantHupHandler(int signal)
{
    LogMessage("Reload via Signal HUP does not work if you aren't root or are chroot'ed\n");
}

static void SigUsrHandler(int signal)
{
    /* Just set a flag that we caught a SIGUSR
     * (or whatever else we handle in here)
     */
    pv.usr_signal = signal;
}

/****************************************************************************
 *
 * Function: CleanExit()
 *
 * Purpose:  Clean up misc file handles and such and exit
 *
 * Arguments: exit value;
 *
 * Returns: void function
 *
 ****************************************************************************/
extern PluginSignalFuncNode *PluginShutdownList;
extern PluginSignalFuncNode *PluginCleanExitList;
extern PluginSignalFuncNode *PluginRestartList;
extern PreprocSignalFuncNode *PreprocShutdownList;
extern PreprocSignalFuncNode *PreprocCleanExitList;
extern PreprocSignalFuncNode *PreprocRestartList;

void CleanExit(int exit_val)
{
    PreprocSignalFuncNode *idxPreproc = NULL;
    PreprocSignalFuncNode *tempPreproc = NULL;
    PluginSignalFuncNode *idxPlugin = NULL;
    PluginSignalFuncNode *tempPlugin = NULL;

    /* This function can be called more than once.  For example,
     * once from the SIGINT signal handler, and once recursively
     * as a result of calling pcap_close() below.  We only need
     * to perform the cleanup once, however.  So the static
     * variable already_exiting will act as a flag to prevent
     * double-freeing any memory.  Not guaranteed to be
     * thread-safe, but it will prevent the simple cases.
     */
    static int already_exiting = 0;
    if( already_exiting != 0 )
    {
        return;
    }
    already_exiting = 1;

#ifdef INLINE_FAILOPEN
    if(pv.pass_thread_running_flag)
    {
        pv.initialization_done_flag = 1;
        pthread_kill(pv.pass_thread_id, SIGKILL);
    }
#endif

    /* Do some post processing on any incomplete Preprocessor Data */
    idxPreproc = PreprocShutdownList;
    while (idxPreproc)
    {
        idxPreproc->func(SIGQUIT, idxPreproc->arg);
        idxPreproc = idxPreproc->next;
    }

    /* Do some post processing on any incomplete Plugin Data */
    idxPlugin = PluginShutdownList;
    while(idxPlugin)
    {
        idxPlugin->func(SIGQUIT, idxPlugin->arg);
        tempPlugin = idxPlugin;
        idxPlugin = idxPlugin->next;
        free(tempPlugin);
    }

    if (pv.done_processing)
    {
        struct timeval difftime;
        struct timezone tz;

        bzero((char *) &tz, sizeof(tz));
        gettimeofday(&endtime, &tz);

        TIMERSUB(&endtime, &starttime, &difftime);

        if ( !pv.quiet_flag )
        {
            printf("Run time for packet processing was %lu.%lu seconds\n", 
                (unsigned long)difftime.tv_sec, (unsigned long)difftime.tv_usec);
        }
    }

#ifdef TIMESTATS
    alarm(0);   /* cancel any existing alarm and disable alarm() function */
#endif

    /* Exit preprocessors */
    idxPreproc = PreprocCleanExitList;
    while(idxPreproc)
    {
        idxPreproc->func(SIGQUIT, idxPreproc->arg);
        tempPreproc = idxPreproc;
        idxPreproc = idxPreproc->next;
        free(tempPreproc);
    }

    /* Print Statistics */
    if(!pv.test_mode_flag)
    {
        fpShowEventStats();
#ifdef PERF_PROFILING
        {
            int quiet_flag_save;
            quiet_flag_save = pv.quiet_flag;
            pv.quiet_flag = 0;
            ShowPreprocProfiles();
            ShowRuleProfiles();
            pv.quiet_flag = quiet_flag_save;
        }
#endif
        DropStats(0);
    }

    /* Exit plugins */
    idxPlugin = PluginCleanExitList;
    //if(idxPlugin)
    //    LogMessage("WARNING: Deprecated Plugin API still in use\n");

#ifdef GIDS
#ifndef IPFW
    if (InlineMode())
    {

        if (ipqh)
        {
            ipq_destroy_handle(ipqh);
        }

    }
#endif /* IPFW (may need cleanup code here) */
#endif /* GIDS */

    while(idxPlugin)
    {
        idxPlugin->func(SIGQUIT, idxPlugin->arg);
        idxPlugin = idxPlugin->next;
    }

    /* free allocated memory */

    /* close pcap */
#ifdef GIDS
    if (pd && !InlineMode())
#else
    if (pd)
#endif
    {
        pcap_close(pd);
        pd = NULL;
    }

    LogMessage("Snort exiting\n");

    ClearDumpBuf();

    /* remove pid file */
    if(pv.pid_filename)
        unlink(pv.pid_filename);

    ClosePidFile();

    /* exit */
    exit(exit_val);
}

static void Restart()
{
    PreprocSignalFuncNode *idxPreproc = NULL;
    PreprocSignalFuncNode *preprocTemp= NULL;
    PluginSignalFuncNode *idxPlugin = NULL;
    PluginSignalFuncNode *plugTemp = NULL;

    /* Exit preprocessors */
    idxPreproc = PreprocRestartList;
    while(idxPreproc)
    {
        idxPreproc->func(SIGHUP, idxPreproc->arg);
        preprocTemp = idxPreproc;
        idxPreproc = idxPreproc->next;
        free(preprocTemp);
    }

    /* Print statistics */
    if(!pv.test_mode_flag)
    {
        fpShowEventStats();
        DropStats(0);
    }

    /* Exit plugins */
    /* legacy exit code */
    idxPlugin = PluginRestartList;
    //if(idxPlugin)
    //    LogMessage("WARNING: Deprecated Plugin API still in use\n");

    while(idxPlugin)
    {
        idxPlugin->func(SIGHUP, idxPlugin->arg);
        plugTemp = idxPlugin;
        idxPlugin = idxPlugin->next;
        free(plugTemp);
    }

    /* free allocated memory */

    /* close pcap */
#ifdef GIDS
    if (pd && !InlineMode())
#else
    if (pd)
#endif
    {
        pcap_close(pd);
        pd = NULL;
    }

    ClearDumpBuf();

    /* remove pid file */
    if(pv.pid_filename)
        unlink(pv.pid_filename);

    LogMessage("Restarting Snort\n");

    /* For pcap_loop to return */
    //pcap_breakloop();

#if 0
    /* re-exec Snort */
#ifdef PARANOID
    execv(progname, progargs);
#else
    execvp(progname, progargs);
#endif

    /* only get here if we failed to restart */
    LogMessage("Restarting %s failed: %s\n", progname, strerror(errno));
    exit(1);
#endif
}

void
InitPcap( int test_flag )
{
#ifndef MUST_SPECIFY_DEVICE    
    if((pv.interface == NULL) && !pv.readmode_flag && !pv.print_version &&
#ifdef DYNAMIC_PLUGIN
        !pv.dump_dynamic_rules_flag &&
#endif
        !pv.test_mode_flag)
    {
        char errorbuf[PCAP_ERRBUF_SIZE];
#ifdef GIDS
        if (!InlineMode())
        {
#endif /* GIDS */
        pv.interface = pcap_lookupdev(errorbuf);

        if(pv.interface == NULL)
            FatalError( "Failed to lookup for interface: %s."
                    " Please specify one with -i switch\n", errorbuf);
        else
            LogMessage("***\n*** interface device lookup found: %s\n***\n",pv.interface);
#ifdef GIDS
        }
#endif /* GIDS */
    }
#else /* MUST_SPECIFY_DEVICE */
    if((pv.interface == NULL) && !pv.readmode_flag && !pv.print_version &&
#ifdef DYNAMIC_PLUGIN
        !pv.dump_dynamic_rules_flag &&
#endif
        !pv.test_mode_flag)
    {
            FatalError( "You must specify either: a network interface (-i), "
#ifdef DYNAMIC_PLUGIN
                        "dump dynamic rules to a file (--dump-dynamic-rules), "
#endif
                        "a capture file (-r), or the test flag (-T)\n");
    }
#endif /* MUST_SPECIFY_DEVICE */

    g_pcap_test = test_flag;

    if(!pv.readmode_flag && !pv.test_mode_flag && !pv.print_version)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "%s interface: %s\n", 
                    test_flag ? "Testing" : "Opening", 
                    PRINT_INTERFACE(pv.interface)););
        /* open up our libpcap packet capture interface */
        OpenPcap();
    }
    else if (!pv.test_mode_flag && !pv.print_version)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "%s file: %s\n", 
                    test_flag ? "Testing" : "Opening", 
                    pv.readfile););

        /* open the packet file for readback */
        OpenPcap();
    }

    /* If test mode, need to close pcap again. */
    if ( test_flag )
    {
#ifdef GIDS
        if (pd && !InlineMode())
#else
        if (pd)
#endif
        {
           pcap_close(pd);
           pd = NULL;
        }
    }
}

