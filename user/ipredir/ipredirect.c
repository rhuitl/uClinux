/*
 *  NETtel IP-Redirection
 *
 *	 Redirects packets to an ip address - see README for full 
 *  explanation
 */

//#include <stdio.h>
//#include <stdlib.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h> /* req by optarg */
#include <getopt.h>
#include <syslog.h>

#define DEBUG			1
#define OUT				0
#define VERSION		"0.2.2"
#define FALSE			0
#define TRUE			1
#define CONFIG_FILE				"/etc/config/config"
#define MAX_CONFIG_LINE_SIZE	128

/* prototypes */
int inSocket(long listen_addr,short listen_port, int protocol);
int outSocket (long send_from_addr, short send_from_port, long send_addr, short send_port, int protocol);
int outSocket2 (long send_from_addr, short send_from_port, int protocol);
int outSocket3 (int protocol);
int parseIp(char *ipstring, long *addr, short *port );
void usage();

int main(int argc, char *argv[]) {

	char value[MAX_CONFIG_LINE_SIZE];
	int socket_in; 
	int socket_out; 
#if DEBUG
	struct in_addr ina_tmp;
#endif
	struct sockaddr_in sin_from;
	int int_from;
	int len = 255;
	int out = FALSE;
	int ourpacket = FALSE;
	int rc,flag;
	unsigned char msg[255];

	//these will be set later by command line options or a config file
	int protocol = IPPROTO_UDP;

	long listen_addr = INADDR_ANY;
	/*short listen_port = 1238;*/
	short listen_port = 0xaa;

	long send_addr = inet_addr("192.168.0.255"); 
	short send_port = 55;
	
	long send_from_addr = INADDR_ANY;
	short send_from_port = 0;
	
	long ignore_addr = INADDR_ANY;
	short ignore_port = 0;
	
	
	
  while ((rc = getopt(argc, argv, "vho?l:s:f:i:")) > 0) {
    switch (rc) {
    case 'v':
      printf("NETtel IP-Redirection (v%s)\n", VERSION);
      exit(0);
      break;
    case 'l': 
		parseIp(optarg, &listen_addr, &listen_port );
		break;
    case 's': 
		parseIp(optarg, &send_addr, &send_port );
		break;
    case 'f': 
		parseIp(optarg, &send_from_addr, &send_from_port );
		break;
    case 'i': 
		parseIp(optarg, &ignore_addr, &ignore_port );
		break;
    case 'o': 
	 	out = 1;
		break;
    case '?':
	 	usage();
		exit(0);
      break;
    case 'h':
	 	usage();
		exit(0);
      break;
    }
  }

	openlog("ipredirect", 0, 0);
	syslog(LOG_INFO, "NETtel IP-Redirection (v%s) started", VERSION);
#if DEBUG
	printf("NETtel IP-Redirection (v%s) started\n", VERSION);
#endif	
	
   socket_out = outSocket(send_from_addr,send_from_port,send_addr,send_port,protocol);
	
	if (!out) { 
		socket_in = inSocket(listen_addr,listen_port,protocol);
	}	
	while(1) { /* loop until your dizzy */

		if (!out) { 
			printf("Waiting for packet...\n");
			if ((len = recvfrom(socket_in,msg,sizeof(msg),0,(struct sockaddr*)&sin_from,&int_from)) == -1) {
				syslog(LOG_ERR, "couldnt recv packet");
#if DEBUG
				perror("couldnt recv packet\n");
#endif			
			}
#if DEBUG
			printf("recieved\n");
			ina_tmp.s_addr = sin_from.sin_addr.s_addr;
			printf("packet from %s\n",inet_ntoa(ina_tmp));
#endif
		}
		
		if (ignore_addr != sin_from.sin_addr.s_addr) {
			printf("Packet accepted!!!!\n");
			//ina_tmp.s_addr = ignore_addr;
			//printf("ignoring %s != ",inet_ntoa(ina_tmp));
			//ina_tmp.s_addr = sin_from.sin_addr.s_addr;
			//printf("packet from %s\n",inet_ntoa(ina_tmp));
			
#if DEBUG
			printf("Sending..len = %d\n",len);
#endif		
			if (send(socket_out,msg,len,0) == -1) {
				//syslog(LOG_ERR, "couldnt send packet");
#if DEBUG
				perror("couldnt send packet");
#endif			
			}
#if DEBUG
			printf("Sent\n");
#endif		
		
#if DEBUG
		}
		else { //if we ignore it
			printf("Packet ignored\n");
		}
#endif		
	}

	close(socket_out);
	if (!out) { 
		close(socket_in);
	}
	closelog();
	return 0; 
}

int inSocket(long listen_addr,short listen_port, int protocol) {
	int n = 1;
	int socket_in;
	struct sockaddr_in sin;
	
	socket_in = socket(PF_INET, SOCK_DGRAM, protocol);
	if(socket_in == -1) {
		syslog(LOG_ERR, "server socket error");
#if DEBUG
		printf("server socket error\n");
#endif		
		exit(0);
	}

	if (setsockopt(socket_in, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1) {
		printf("couldnt set option\n");
	}

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(listen_port);
	sin.sin_addr.s_addr = listen_addr;

	if(bind(socket_in, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1) {
		syslog(LOG_ERR, "sock_listen bind error");
#if DEBUG
		perror("sock_listen bind error -");
#endif		
		exit(0);
	}
	
	return socket_in;	
}


int outSocket (long send_from_addr, short send_from_port, long send_addr, short send_port, int protocol) {
	int n = 2;
	int send_socket;
	struct sockaddr_in sin;
	
	send_socket = socket(PF_INET, SOCK_DGRAM, protocol);
	if(send_socket == -1) {
		syslog(LOG_ERR, "send socket err");
#if DEBUG
		printf("snd socket error\n");
#endif		
		exit(0);
	}

	if (setsockopt(send_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1) {
		syslog(LOG_ERR, "Couldnt set socket option");
#if DEBUG
		printf("couldnt set option\n");
#endif		
	}

	if (setsockopt(send_socket, SOL_SOCKET, SO_BROADCAST, (char *) &n, sizeof(n)) == -1) {
		syslog(LOG_ERR, "Couldnt set socket option");
#if DEBUG
		printf("couldnt set option\n");
#endif		
	}

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(send_from_port);
	sin.sin_addr.s_addr = send_from_addr;
	
	if(bind(send_socket,(struct sockaddr *)&sin, sizeof(struct sockaddr))==-1)
	{
		syslog(LOG_ERR, "send bind error");
#if DEBUG
		perror("sock_send bind error -");
#endif		
		exit(0);
	}
	
	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(send_port);
	sin.sin_addr.s_addr = send_addr; /*INADDR_BROADCAST*/

	if(connect(send_socket, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1) {
		syslog(LOG_ERR, "send connect error");
#if DEBUG
		perror("send connect error\n");
#endif		
		exit(0);
	} 

	return send_socket;	
}

int outSocket2 (long send_from_addr, short send_from_port, int protocol) {

	int n = 2;
	int send_socket;
	struct sockaddr_in sin;
	
	send_socket = socket(PF_INET, SOCK_DGRAM, protocol);
	if(send_socket == -1) {
		syslog(LOG_ERR, "send socket err");
#if DEBUG
		printf("snd socket error\n");
#endif		
		exit(0);
	}

	if (setsockopt(send_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1) {
		syslog(LOG_ERR, "Couldnt set socket option");
#if DEBUG
		printf("couldnt set option\n");
#endif		
	}

	if (setsockopt(send_socket, SOL_SOCKET, SO_BROADCAST, (char *) &n, sizeof(n)) == -1) {
		syslog(LOG_ERR, "Couldnt set socket option");
#if DEBUG
		printf("couldnt set option\n");
#endif		
	}

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(send_from_port);
	sin.sin_addr.s_addr = send_from_addr;
	
	if(bind(send_socket,(struct sockaddr *)&sin, sizeof(struct sockaddr))==-1)
	{
		syslog(LOG_ERR, "send bind error");
#if DEBUG
		perror("sock_send bind error -");
#endif		
		exit(0);
	}
		
	return send_socket;	
}
/////////////////////////////////////////////////////

int outSocket3 (int protocol) {

	int n = 2;
	int send_socket;
	struct sockaddr_in sin;
	
	send_socket = socket(PF_INET, SOCK_DGRAM, protocol);
	if(send_socket == -1) {
		syslog(LOG_ERR, "send socket err");
#if DEBUG
		printf("snd socket error\n");
#endif		
		exit(0);
	}

	if (setsockopt(send_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1) {
		syslog(LOG_ERR, "Couldnt set socket option");
#if DEBUG
		printf("couldnt set option\n");
#endif		
	}

	if (setsockopt(send_socket, SOL_SOCKET, SO_BROADCAST, (char *) &n, sizeof(n)) == -1) {
		syslog(LOG_ERR, "Couldnt set socket option");
#if DEBUG
		printf("couldnt set option\n");
#endif		
	}
		
	return send_socket;	
}

////////////////////////////////////////////////////

int parseIp(char *ipstring, long *addr, short *port ) {
	
	int i = 0;
	struct in_addr inaddr;

	char *addrPtr;
	
	*port = 0; //defaults
	*addr = INADDR_ANY; //defaults
	
	addrPtr = ipstring;

	while ((ipstring[i] != '\0') && (ipstring[i] != ':')) {
		i++;
	}
	
	/* Parse Port */
	if (ipstring[i] = ':') {  /* see if there is a port field */
		ipstring[i] = '\0';
		i++;
		ipstring += i; /* change the ptr */
		*port = atoi(ipstring);
	}

	/* Parse Address */
	if (addrPtr[0] != '0') { /* see if they typed an address */
		if (inet_aton(addrPtr,&inaddr) == 0) {
			syslog(LOG_ERR, "Parse error - exiting");
#if DEBUG
			printf("Parse error - exiting\n");
#endif			
			exit(-1);
		}
		*addr = inaddr.s_addr;
	}
}

void usage() {
	printf("ipredirect [-ovh] -l listen_addr -s send_addr [-f send_from_address]\n");
}

/*
 * search_config_file
 *
 * This function opens up the file specified 'filename' and searches
 * through the file for 'keyword'. If 'keyword' is found any string
 * following it is stored in 'value'.. If 'value' is NULL we assume
 * the function was called simply to determing if the keyword exists
 * in the file.
 *
 * args: filename (IN) - config filename
 *	 keyword (IN) - word to search for in config file
 *	 value (OUT) - value of keyword (if value not NULL)
 *
 * retn:	-1 on error,
 *			0 if keyword not found,
 *			1 if found
 */
 
 

