#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <time.h>
#include <net/if.h>
#include <upnp/upnp.h>
#include "globals.h"
#include "config.h"
#include "gatedevice.h"
#include "util.h"
#include "pmlist.h"

// Global variables
struct GLOBALS g_vars;

#define STATE_FILE "/var/run/upnpd.state"

int  g_debug;
char g_downstreamBitrate[10];
char g_extInterfaceName[10];
char g_forwardChainName[20];
int  g_forwardRules;
char g_intInterfaceName[10];
char g_iptables[50];
char g_preroutingChainName[20];
char g_upstreamBitrate[10];

void cleanup(void)
{
	unlink(STATE_FILE);
}

int main (int argc, char** argv)
{
	char descDocUrl[7+15+1+5+1+sizeof(g_vars.descDocName)+1]; // http://ipaddr:port/docName<null>
	char intIpAddress[16];     // Server internal ip address
	char extIpAddress[16];     // Server internal ip address
	sigset_t sigsToCatch;
	int ret, signum, arg = 1, foreground = 0;
	FILE *f;

	if (argc < 3 || argc > 4) {
	  printf("Usage: upnpd [-f] <external ifname> <internal ifname>\n");
	  printf("  -f\tdon't daemonize\n");
	  printf("Example: upnpd ppp0 eth0\n");
	  exit(0);
	}

	parseConfigFile(&g_vars);

	// check for '-f' option
	if (strcmp(argv[arg], "-f") == 0) {
		foreground = 1;
		arg++;
	}

	// Save interface names for later use
	strncpy(g_vars.extInterfaceName, argv[arg++], IFNAMSIZ);
	strncpy(g_vars.intInterfaceName, argv[arg++], IFNAMSIZ);

	openlog("upnpd", LOG_PID | LOG_CONS, LOG_USER);

	// Get the internal ip address to start the daemon on
	if (GetIpAddressStr(intIpAddress, g_vars.intInterfaceName) == 0) {
		fprintf(stderr, "Invalid internal interface name '%s'\n", g_vars.intInterfaceName);
		exit(EXIT_FAILURE);
	}
	if (GetIpAddressStr(extIpAddress, g_vars.extInterfaceName) == 0) {
		fprintf(stderr, "Invalid extneral interface name '%s'\n", g_vars.extInterfaceName);
		exit(EXIT_FAILURE);
	}

	if (!foreground) {
		struct rlimit resourceLimit = { 0, 0 };
		pid_t pid, sid;
		unsigned int i;

		// Put igd in the background as a daemon process.
		pid = fork();
		if (pid < 0)
		{
			perror("Error forking a new process.");
			exit(EXIT_FAILURE);
		}
		if (pid > 0)
			exit(EXIT_SUCCESS);

		// become session leader
		if ((sid = setsid()) < 0)
		{
			perror("Error running setsid");
			exit(EXIT_FAILURE);
		}

		// close all file handles
		resourceLimit.rlim_max = 0;
		ret = getrlimit(RLIMIT_NOFILE, &resourceLimit);
		if (ret == -1) /* shouldn't happen */
		{
		    perror("error in getrlimit()");
		    exit(EXIT_FAILURE);
		}
		if (0 == resourceLimit.rlim_max)
		{
		    fprintf(stderr, "Max number of open file descriptors is 0!!\n");
		    exit(EXIT_FAILURE);
		}	
		for (i = 0; i < resourceLimit.rlim_max; i++)
		    close(i);
	
		// fork again so child can never acquire a controlling terminal
		pid = fork();
		if (pid < 0)
		{
			perror("Error forking a new process.");
			exit(EXIT_FAILURE);
		}
		if (pid > 0)
			exit(EXIT_SUCCESS);
	
		if ((chdir("/")) < 0)
		{
			perror("Error setting root directory");
			exit(EXIT_FAILURE);
		}
	}

	umask(0);

// End Daemon initialization

	openlog("upnpd", LOG_CONS | LOG_NDELAY | LOG_PID | (foreground ? LOG_PERROR : 0), LOG_LOCAL6);

	//open a state file
	f = fopen(STATE_FILE, "w");
	if (!f) {
		syslog(LOG_ERR, "failed to open %s: %m", STATE_FILE);
	} else {
		fprintf(f, "external %s %s\ninternal %s %s\n",
			g_vars.extInterfaceName, extIpAddress,
			g_vars.intInterfaceName, intIpAddress);
		fclose(f);
	}
	atexit(cleanup);

	// Initialize UPnP SDK on the internal Interface
	trace(3, "Initializing UPnP SDK ... ");
	if ( (ret = UpnpInit(intIpAddress,0) ) != UPNP_E_SUCCESS)
	{
		syslog (LOG_ERR, "Error Initializing UPnP SDK on IP %s ",intIpAddress);
		syslog (LOG_ERR, "  UpnpInit returned %d", ret);
		UpnpFinish();
		exit(1);
	}
	trace(2, "UPnP SDK Successfully Initialized.");

	// Set the Device Web Server Base Directory
	trace(3, "Setting the Web Server Root Directory to %s",g_vars.xmlPath);
	if ( (ret = UpnpSetWebServerRootDir(g_vars.xmlPath)) != UPNP_E_SUCCESS )
	{
		syslog (LOG_ERR, "Error Setting Web Server Root Directory to: %s", g_vars.xmlPath);
		syslog (LOG_ERR, "  UpnpSetWebServerRootDir returned %d", ret); 
		UpnpFinish();
		exit(1);
	}
	trace(2, "Succesfully set the Web Server Root Directory.");

	//initialize the timer thread for expiration of mappings
	if (ExpirationTimerThreadInit()!=0) {
	  syslog(LOG_ERR,"ExpirationTimerInit failed");
	  UpnpFinish();
	  exit(1);
	}

	// Form the Description Doc URL to pass to RegisterRootDevice
	sprintf(descDocUrl, "http://%s:%d/%s", UpnpGetServerIpAddress(),
				UpnpGetServerPort(), g_vars.descDocName);

	// Register our IGD as a valid UPnP Root device
	trace(3, "Registering the root device with descDocUrl %s", descDocUrl);
	if ( (ret = UpnpRegisterRootDevice(descDocUrl, EventHandler, &deviceHandle,
					   &deviceHandle)) != UPNP_E_SUCCESS )
	{
		syslog(LOG_ERR, "Error registering the root device with descDocUrl: %s", descDocUrl);
		syslog(LOG_ERR, "  UpnpRegisterRootDevice returned %d", ret);
		UpnpFinish();
		exit(1);
	}

	trace(2, "IGD root device successfully registered.");
	
	// Initialize the state variable table.
	StateTableInit(descDocUrl);
	
	// Record the startup time, for uptime
	startup_time = time(NULL);
	
	// Send out initial advertisements of our device's services with timeouts of 30 minutes
	if ( (ret = UpnpSendAdvertisement(deviceHandle, 1800) != UPNP_E_SUCCESS ))
	{
		syslog(LOG_ERR, "Error Sending Advertisements.  Exiting ...");
		UpnpFinish();
		exit(1);
	}
	trace(2, "Advertisements Sent.  Listening for requests ... ");
	
	// Loop until program exit signals received
	do {
	  sigemptyset(&sigsToCatch);
	  sigaddset(&sigsToCatch, SIGINT);
	  sigaddset(&sigsToCatch, SIGTERM);
	  sigaddset(&sigsToCatch, SIGUSR1);
	  pthread_sigmask(SIG_SETMASK, &sigsToCatch, NULL);
	  sigwait(&sigsToCatch, &signum);
	  trace(3, "Caught signal %d...\n", signum);
	  switch (signum) {
	  case SIGUSR1:
	    pmlist_RecreateAll();
	    break;
	  default:
	    break;
	  }
	} while (signum!=SIGTERM && signum!=SIGINT);

	trace(2, "Shutting down on signal %d...\n", signum);

	// Cleanup UPnP SDK and free memory
	DeleteAllPortMappings();
	ExpirationTimerThreadShutdown();

	UpnpUnRegisterRootDevice(deviceHandle);
	UpnpFinish();

	// Exit normally
	return (0);
}
