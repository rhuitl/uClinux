/*
 * @(#) jig to exercise a UML/FreeSWAN kernel with two interfaces
 *
 * Copyright (C) 2001 Michael Richardson  <mcr@freeswan.org>
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
 * RCSID $Id: uml_netjig.c,v 1.8 2002/01/21 01:08:41 mcr Exp $
 *
 * @(#) based upon uml_router from User-Mode-Linux tools package
 *
 */

/* 
 * This file contains a program to excersize a FreeSWAN kernel that is
 * built in a User-Mode-Linux form. It creates four sets of Unix
 * domain sockets: two control sockets and two data sockets. 
 *
 * These sockets make up the connection points for the "daemon" method
 * of networking provided by UML.
 *
 * The first connection is intended to connect to "eth0" (the inside
 * or "private" network) and the second one to "eth1" (the outside or
 * "public" network).
 *
 * Packets are fed into one network interface from a (pcap) capture file and
 * are captured from the other interface into a pcap capture file.
 *
 * The program can take an argument which is a script/program to run
 * with the appropriate UML arguments. This can be the UML kernel
 * itself, a script that invokes it or something that just records
 * things.
 *
 * The environment variables UML_{public,private}_{CTL,DATA} are set to
 * the names of the respective sockets. 
 *
 * If the --arp option is given, the program will respond to all ARP
 * requests that it sees, providing a suitable response.
 *
 * Note that the program continues to operate as a switch and will
 * accept multiple connections. All packets are logged and the
 * outgoing packets are sent to wherever the destination MAC address
 * specifies.
 *
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#define _GNU_SOURCE 1
#include <getopt.h>

#include "pcap.h"
#include <sys/queue.h>

#define ETH_ALEN 6

#define MAX(x,y) ((x) > (y) ? (x) : (y))

#ifdef NETDISSECT
#include "netdissect.h"

struct netdissect_options gndo;
int tcpdump_print = 1;
#endif

struct connection {
	TAILQ_ENTRY(connection) link;
	int                     active;
	int                     control;
	struct sockaddr_un      name;
	unsigned char addr[ETH_ALEN];
};

enum request_type { REQ_NEW_CONTROL };

struct request {
  enum request_type type;
  union {
    struct {
      unsigned char addr[ETH_ALEN];
      struct sockaddr_un name;
    } new_control;
    struct {
      unsigned long cookie;
    } new_data;
  } u;
};

struct packet {
  struct {
    unsigned char dest[6];
    unsigned char src[6];
    u_int16_t     proto;
  } header;
  unsigned char data[1500];
};

struct nethub {
	TAILQ_HEAD(,connection) connections;
	char              *nh_name;
  unsigned char            nh_defaultether[6];
  struct in_addr           nh_defaultgate;
  int                      nh_allarp;
	char              *nh_outputFile;
	pcap_dumper_t     *nh_output;
	char              *nh_inputFile;
	pcap_t            *nh_input;
	char              *ctl_socket_name;
	int                ctl_listen_fd;
	char              *data_socket_name;
	int                data_fd;
};

struct nethub public, private;

static fd_set perm_fds;
static int max_fd = -1;
static char *progname;

void *xmalloc1(size_t size, char *file, int linenum)
{
	void *space;

	space = malloc(size);
	if(space == NULL) {
		fprintf(stderr, "no memory allocating %d bytes at %s:%d\n",
			size, file, linenum);
		exit(1);
	}
	return space;
}

#define xmalloc(X) xmalloc1((X), __FILE__, __LINE__)

static void cleanup(struct nethub *nh)
{
  if(unlink(nh->ctl_socket_name) < 0){
    printf("Couldn't remove control socket '%s' : %s\n",
	   nh->ctl_socket_name, strerror(errno));
  }
  if(unlink(nh->data_socket_name) < 0){
    printf("Couldn't remove data socket '%s' : %s\n",
	   nh->data_socket_name, strerror(errno));
  }
}

static void sig_handler(int sig)
{
  printf("Caught signal %d, cleaning up and exiting\n", sig);
  cleanup(&public);
  cleanup(&private);
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}

static void close_descriptor(int fd)
{
  FD_CLR(fd, &perm_fds);
  close(fd);
}

static void free_connection(struct nethub *nh,
			    struct connection *conn)
{
  close_descriptor(conn->control);
  FD_CLR(conn->control, &perm_fds);

  TAILQ_REMOVE(&nh->connections, conn, link);

  free(conn);
}

static void service_connection(struct nethub *nh,
			       struct connection *conn)
{
  struct request req;
  int n;

  n = read(conn->control, &req, sizeof(req));
  if(n < 0){
    perror("Reading request");
    free_connection(nh, conn);
    return;
  }
  else if(n == 0){
    printf("%s: disconnect from hw address %02x:%02x:%02x:%02x:%02x:%02x\n",
	   nh->nh_name,
	   conn->addr[0], conn->addr[1], conn->addr[2], conn->addr[3], 
	   conn->addr[4], conn->addr[5]);
    free_connection(nh, conn);
    return;
  }    
  switch(req.type){
  case REQ_NEW_CONTROL:
    memcpy(conn->addr, req.u.new_control.addr, sizeof(conn->addr));
    conn->name = req.u.new_control.name;
    conn->active = 1;

    printf("%s: new connection - hw address %02x:%02x:%02x:%02x:%02x:%02x\n",
	   nh->nh_name,
	   conn->addr[0], conn->addr[1], conn->addr[2], conn->addr[3], 
	   conn->addr[4], conn->addr[5]);
    break;
  default:
    printf("Bad request type : %d\n", req.type);
    free_connection(nh, conn);
  }
}

static int match_addr(unsigned char *host, unsigned char *packet)
{
  if(packet[0] & 1) return(1);
  return((packet[0] == host[0]) && (packet[1] == host[1]) && 
	 (packet[2] == host[2]) && (packet[3] == host[3]) && 
	 (packet[4] == host[4]) && (packet[5] == host[5]));
}

static void forward_data(struct nethub *nh,
			 struct packet *p,
			 int    len)
{
  struct connection *c, *next;

  for(c = nh->connections.tqh_first; c != NULL; c = next){
    next = c->link.tqe_next;
    if(c->active &&
       match_addr(c->addr, p->header.dest)){
      sendto(nh->data_fd, p, len,
	     0, (struct sockaddr *) &c->name, sizeof(c->name));
    }
  }
}

static void handle_data(struct nethub *nh)
{
  struct pcap_pkthdr ph;
  struct packet p;
  int len;

  len = recvfrom(nh->data_fd, &p, sizeof(p), 0, NULL, 0);
  if(len < 0){
    if(errno != EAGAIN) perror("Reading data");
    return;
  }

  memset(&ph, 0, sizeof(ph));
  ph.caplen = len;
  ph.len    = len;

  if(nh->nh_outputFile) {
    pcap_dump((u_char *)nh->nh_output, &ph, (u_char *)&p);
  }

#ifdef NETDISSECT
  /* now dump it to tcpdump dissector if one was configured */
  if(tcpdump_print) {
    printf("%8s:", nh->nh_name);
    ether_if_print((u_char *)&gndo, &ph, (u_char *)&p);
  }
#endif

#ifdef ARP_PROCESS
  if(nh->nh_defaultgate.s_addr!=0 || nh->nh_allarp) {
    if(p.header.proto == htons(ETHERTYPE_ARP)) {
      struct arphdr *ahdr;
      
      ahdr = (struct arphdr *)&p.data;
      if(ahdr->ar_hrd == htons(ARPHRD_ETHER) &&
	 ahdr->ar_pro == htons(ETHERTYPE_IP) &&
	 ahdr->ar_hln == ETH_ALEN &&
	 ahdr->ar_pln == 4 &&
	 ahdr->ar_op  == htons(ARPOP_REQUEST)) {
	u_int32_t *tip;
	u_int32_t *sip;
	sip = (u_int32_t *)(p.data + /*sizeof(arphdr)*/8 + 1*ETH_ALEN);
	tip = (u_int32_t *)(p.data + /*sizeof(arphdr)*/8 + 2*ETH_ALEN + 4);

	if(nh->nh_allarp == 1 || *tip == nh->nh_defaultgate.s_addr) {
	  /* AHA! reply to ARP request */
	  
	  /* we mutate this packet in place */
	  /* change this to a reply */
	  ahdr->ar_op = htons(ARPOP_REPLY);

	  /* swap ether fields */
	  memcpy(p.header.dest, p.header.src, ETH_ALEN);

	  memcpy(p.data + 8, nh->nh_defaultether, ETH_ALEN);
	  memcpy(p.header.src, nh->nh_defaultether, ETH_ALEN);

	  /* swap ip fields */
	  {
	    uint32_t tmp;
	    tmp=*sip;
	    *sip=*tip;
	    *tip=tmp;
	  }

	  printf("%s: found ARP request, replying: \n", nh->nh_name);
#ifdef NETDISSECT
	  if(tcpdump_print) {
	    struct pcap_pkthdr ph;

	    memset(&ph, 0, sizeof(ph));
	    
	    ph.caplen = len;
	    ph.len    = len;

	    printf("%8s:", nh->nh_name);
	    ether_if_print((u_char *)&gndo, &ph, (u_char *)&p);
	  }
#endif
	}
      }
    }
  }
#endif
  forward_data(nh, &p, len);

}

static void new_connection(struct nethub *nh,
			   int fd)
{
  struct connection *conn;

  conn = xmalloc(sizeof(struct connection));
  if(conn == NULL){
	  perror("malloc");
	  close_descriptor(fd);
	  return;
  }

  conn->control = fd;
  conn->active = 0;
  conn->addr[0]=0xff;

  TAILQ_INSERT_TAIL(&nh->connections, conn, link);
}

void handle_connections(struct nethub *nh,
			fd_set *fds, int max)
{
  struct connection *c;
  int i;

  for(i=0;i<max;i++){
    if(FD_ISSET(i, fds)){
      
      for(c = nh->connections.tqh_first;
	  c != NULL;
	  c = c->link.tqe_next)
      {
	      if(c->control == i){
		      service_connection(nh, c);
		      break;		      
	      }
      }
    }
  }
}


void accept_connection(struct nethub *nh)
{
  struct sockaddr addr;
  int len, new;

  new = accept(nh->ctl_listen_fd, &addr, &len);
  if(new < 0){
    perror("accept");
    return;
  }
  if(fcntl(new, F_SETFL, O_NONBLOCK) < 0){
    perror("fcntl - setting O_NONBLOCK");
    close(new);
    return;
  }
  if(new > max_fd) max_fd = new;
  FD_SET(new, &perm_fds);

  new_connection(nh, new);
}


int still_used(struct sockaddr_un *sun)
{
  int test_fd, ret = 1;

  if((test_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
    perror("socket");
    exit(1);
  }

  if(connect(test_fd, (struct sockaddr *) sun, sizeof(*sun)) < 0){
    if(errno == ECONNREFUSED){
      if(unlink(sun->sun_path) < 0){
	fprintf(stderr, "Failed to removed unused socket '%s': ", 
		sun->sun_path);
	perror("");
      }
      ret = 0;
    }
    else perror("connect");
  }
  close(test_fd);
  return(ret);
}


int bind_socket(int fd, const char *name)
{
  struct sockaddr_un sun;

  sun.sun_family = AF_UNIX;
  strcpy(sun.sun_path, name);
  
  if(bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
    if((errno == EADDRINUSE) && still_used(&sun)) return(EADDRINUSE);
    else if(bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
      perror("bind");
      return(EPERM);
    }
  }
  return(0);
}


void bind_sockets(struct nethub *nh)
{
  int ctl_err, ctl_present = 0, ctl_used = 0;
  int data_err, data_present = 0, data_used = 0;
  int try_remove_ctl, try_remove_data;

  ctl_err = bind_socket(nh->ctl_listen_fd, nh->ctl_socket_name);
  if(ctl_err != 0) ctl_present = 1;
  if(ctl_err == EADDRINUSE) ctl_used = 1;

  data_err = bind_socket(nh->data_fd, nh->data_socket_name);
  if(data_err != 0) data_present = 1;
  if(data_err == EADDRINUSE) data_used = 1;

  if(!ctl_err && !data_err) return;

  unlink(nh->ctl_socket_name);
  unlink(nh->data_socket_name);

  try_remove_ctl = ctl_present;
  try_remove_data = data_present;
  if(ctl_present && ctl_used){
    fprintf(stderr, "The control socket '%s' has another server "
	    "attached to it\n", nh->ctl_socket_name);
    try_remove_ctl = 0;
  }
  else if(ctl_present && !ctl_used)
    fprintf(stderr, "The control socket '%s' exists, isn't used, but couldn't "
	    "be removed\n", nh->ctl_socket_name);
  if(data_present && data_used){
    fprintf(stderr, "The data socket '%s' has another server "
	    "attached to it\n", nh->data_socket_name);
    try_remove_data = 0;
  }
  else if(data_present && !data_used)
    fprintf(stderr, "The data socket '%s' exists, isn't used, but couldn't "
	    "be removed\n", nh->data_socket_name);
  if(try_remove_ctl || try_remove_data){
    fprintf(stderr, "You can either\n");
    if(try_remove_ctl && !try_remove_data) 
      fprintf(stderr, "\tremove '%s'\n", nh->ctl_socket_name);
    else if(!try_remove_ctl && try_remove_data) 
      fprintf(stderr, "\tremove '%s'\n", nh->data_socket_name);
    else fprintf(stderr, "\tremove '%s' and '%s'\n",
		 nh->ctl_socket_name, nh->data_socket_name);
    fprintf(stderr, "\tor rerun with different, unused filenames for "
	    "sockets:\n");
    fprintf(stderr, "\t\t%s -unix <control> <data>\n", progname);
    fprintf(stderr, "\t\tand run the UMLs with "
	    "'eth0=daemon,,unix,<control>,<data>\n");
    exit(1);
  }
  else {
    fprintf(stderr, "You should rerun with different, unused filenames for "
	    "sockets:\n");
    fprintf(stderr, "\t%s -unix <control> <data>\n", progname);
    fprintf(stderr, "\tand run the UMLs with "
	    "'eth0=daemon,,unix,<control>,<data>'\n");
    exit(1);
  }
}

static void Usage(void)
{
  fprintf(stderr, "Usage : uml_netjig \n"
	  "Version $Revision: 1.8 $ \n\n"
      "\t--exitonempty (-e)          exit when no more packets to read\n"
      "\t--playpublic (-p) <file>    pcap(3) file to feed into public side\n"
      "\t--recordpublic (-r) <file>  pcap(3) file to write from public side\n"
      "\t--playprivate (-P) <file>   pcap(3) file to feed into private side\n"
      "\t--recordprivate (-R) <file> pcap(3) file to write from private side\n"
      "\t--unix (-u) <dir>           directory to put sockets (default $TMPDIR)\n"
      "\t--startup (-s) <script>     script to run after sockets are setup.\n"
#ifdef NETDISSECT
	  "\t--tcpdump (-t)           dump packets with tcpdump-dissector\n"
#else
	  "\t--tcpdump (-t)           (not available - dissector not built in)\n"
#endif
#ifdef ARP_PROCESS
	  "\t--arpreply (-a)          respond to ARP requests\n"
#else
	  "\t--arpreply (-a)          (not available - arp replies disabled)\n"
#endif
	  "\t--help                   this message\n\n");
  exit(1);
}

#ifdef NETDISSECT
/* Like default_print() but data need not be aligned */
void
default_print_unaligned(struct netdissect_options *ipdo,
			register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	if (ipdo->ndo_Xflag) {
		ascii_print(ipdo, cp, length);
		return;
	}
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(struct netdissect_options *ndo,
	      register const u_char *bp, register u_int length)
{
	default_print_unaligned(ndo, bp, length);
}
#endif

void init_nethub(struct nethub *nh, char *base, char *type)
{
	int one;
	char *env;

	one = 1;

	memset(nh, 0, sizeof(*nh));
	TAILQ_INIT(&nh->connections);

	nh->nh_name = strdup(type);

	/* setup ARP stuff */
	nh->nh_allarp = 0;
	
	nh->nh_defaultgate.s_addr = 0;
	
	nh->nh_defaultether[0]=0x10;
	nh->nh_defaultether[1]=0x00;
	nh->nh_defaultether[2]=0x00;
	nh->nh_defaultether[3]=type[0];
	nh->nh_defaultether[4]=type[1];
	nh->nh_defaultether[5]=type[2];

	/* cons up the names, and stick them in the environment */
	env = xmalloc(sizeof("UML_")+strlen(type)+sizeof("CTL=")+
		      strlen(base)+sizeof("/ctl")+1);

	sprintf(env, "UML_%s_CTL=%s/ctl", type, base);
	nh->ctl_socket_name = strchr(env, '=')+1;
	putenv(env);

	env = xmalloc(sizeof("UML_")+strlen(type)+sizeof("DATA=")+
		      strlen(base)+sizeof("/data")+1);

	sprintf(env, "UML_%s_DATA=%s/data", type, base);
	nh->data_socket_name = strchr(env, '=')+1;
	putenv(env);

	if((nh->ctl_listen_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
		perror("socket");
		exit(1);
	}
	if(setsockopt(nh->ctl_listen_fd,
		      SOL_SOCKET, SO_REUSEADDR, (char *) &one, 
		      sizeof(one)) < 0){
		perror("setsockopt");
		exit(1);
	}

	if(fcntl(nh->ctl_listen_fd, F_SETFL, O_NONBLOCK) < 0){
		perror("Setting O_NONBLOCK on connection fd");
		exit(1);
	}
	
	if((nh->data_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0){
		perror("socket");
		exit(1);
	}
	if(fcntl(nh->data_fd, F_SETFL, O_NONBLOCK) < 0){
		perror("Setting O_NONBLOCK on data fd");
		exit(1);
	}

	bind_sockets(nh);

	if(listen(nh->ctl_listen_fd, 15) < 0){
		perror("listen");
		exit(1);
	}
	
}

static int debug=0;

int main(int argc, char **argv)
{
  int n, done;
  int  exitonempty;
  char *publicbase, *privatebase;
  char *basedir, *startup;
  char *playprivatefile, *recordprivatefile;
  char *playpublicfile, *recordpublicfile;
  int   publicturn;
  char errbuf[256];
  int opt;
  int arpreply;
  static struct option long_options[] =
  {
    {"help",        no_argument, 0, 'h'},
    {"arpreply",    no_argument, 0, 'a'},
    {"debug",       no_argument, 0, 'd'},
    {"exitonempty", no_argument, 0, 'e'},
    {"tcpdump",     no_argument, 0, 't'},
    {"playpublic", required_argument, 0, 'p'},
    {"playprivate",required_argument, 0, 'P'},
    {"recordpublic",  required_argument, 0, 'r'},
    {"recordprivate", required_argument, 0, 'R'},
    {"unix",    required_argument, 0, 'u'},
    {"startup", required_argument, 0, 's'},
  };
  

  basedir    = NULL;
  publicbase = NULL;
  privatebase= NULL;
  startup    = NULL;
  arpreply   = 0;
  exitonempty= 0;
  playpublicfile  = playprivatefile   = NULL;
  recordpublicfile= recordprivatefile = NULL;

  progname = argv[0];
  if(strrchr(progname, '/')) {
	  progname=strrchr(progname, '/')+1;
  }

  while((opt = getopt_long(argc, argv, "adehp:P:r:R:s:tu:",
			   long_options, NULL)) !=  EOF) {
    switch(opt) {
    case 'a':
	    arpreply++;
	    break;
    case 'd':
	    debug++;
	    break;
    case 'e':
	    exitonempty++;
	    break;
    case 'u':
	    basedir = optarg;
	    break;
    case 's':
	    startup = optarg;
	    break;
	    
    case 't':
	    fprintf(stderr, "tcpdump dissector not available\n");
#ifdef NETDISSECT
	    tcpdump_print = 1;
#endif
	    break;

    case 'p':
      playpublicfile = optarg;
      break;

    case 'P':
      playprivatefile = optarg;
      break;

    case 'r':
      recordpublicfile= optarg;
      break;

    case 'R':
      recordprivatefile= optarg;
      break;

    case 'h':
    default:
      Usage();
    }
  }

  if(basedir == NULL) {
    n=1000;
    while(n>0) {
      basedir=tempnam(NULL, "uml");
      if(mkdir(basedir, 0700) == 0) {
	break;
      }
      n--;
    }
    if(n==0) {
      fprintf(stderr, "failed to make tmpdir (last=%s)\n",
	      basedir);
      exit(1);
    }
  }
  
  if(!publicbase) {
    publicbase=xmalloc(strlen(basedir)+sizeof("/public")+1);
    sprintf(publicbase, "%s/public", basedir);
    if(mkdir(publicbase, 0700) != 0 && errno!=EEXIST) {
      perror(publicbase);
      exit(1);
    }
  }
  
  if(!privatebase) {
    privatebase=xmalloc(strlen(basedir)+sizeof("/private")+1);
    sprintf(privatebase, "%s/private", basedir);
    if(mkdir(privatebase, 0700) != 0 && errno!=EEXIST) {
      perror(privatebase);
      exit(1);
    }
  }
  
#ifdef NETDISSECT	  
  memset(&gndo, 0, sizeof(gndo));
  gndo.ndo_default_print = default_print;

  /* dump ethernet headers */
  gndo.ndo_eflag = 1;

  /* avoid DNS lookups */
  gndo.ndo_nflag = 0;
#endif

  init_nethub(&public, publicbase, "public");
  init_nethub(&private,privatebase,"private");

  public.nh_allarp = arpreply;
  private.nh_allarp= arpreply;

  if(recordpublicfile) {
	  pcap_t *pt;

	  printf("%s: will record to %s from public interface\n",
		 progname, recordpublicfile);
	  public.nh_outputFile = recordpublicfile;

	  pt = pcap_open_dead(DLT_EN10MB, 1536);
	  public.nh_output = pcap_dump_open(pt, recordpublicfile);
	  if(public.nh_output == NULL) {
	    fprintf(stderr, "pcap_dump_open failed to open %s\n",
		    recordpublicfile);
	    exit(1);
	  }
  }

  if(recordprivatefile) {
	  pcap_t *pt;

	  printf("%s: will record to %s from private interface\n",
		 progname, recordprivatefile);
	  private.nh_outputFile = recordprivatefile;

	  pt = pcap_open_dead(DLT_EN10MB, 1536);
	  private.nh_output = pcap_dump_open(pt, recordprivatefile);
	  if(private.nh_output == NULL) {
	    fprintf(stderr, "pcap_dump_open failed to open %s\n",
		    recordprivatefile);
	    exit(1);
	  }
  }

  if(playpublicfile) {
	  printf("%s: will play %s to public interface\n",
		 progname, playpublicfile);

	  public.nh_inputFile = playpublicfile;
	  public.nh_input = pcap_open_offline(playpublicfile, errbuf);
	  if(public.nh_input == NULL) {
		  fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
		  exit(1);
	  }
  }	  

  if(playprivatefile) {
	  printf("%s: will play %s to private interface\n",
		 progname, playprivatefile);

	  private.nh_inputFile = playprivatefile;
	  private.nh_input = pcap_open_offline(playprivatefile, errbuf);
	  if(private.nh_input == NULL) {
		  fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
		  exit(1);
	  }
  }	  

  printf("%s: will exit on empty: %s\n", progname,
	 exitonempty ? "yes" : "no ");

  if(signal(SIGINT, sig_handler) < 0)
    perror("Setting handler for SIGINT");

  if(startup) {
	  system(startup);
  }

  printf("%s attached to unix sockets \n\t'%s,%s'\n and \n\t'%s,%s'\n",
	 progname, public.ctl_socket_name, public.data_socket_name,
	 private.ctl_socket_name, private.data_socket_name);

  FD_ZERO(&perm_fds);

  if(isatty(0)) FD_SET(0, &perm_fds);

  FD_SET(public.ctl_listen_fd, &perm_fds);
  FD_SET(private.ctl_listen_fd, &perm_fds);
  FD_SET(public.data_fd, &perm_fds);
  FD_SET(private.data_fd, &perm_fds);

  max_fd = -1;
  max_fd = MAX(max_fd,  public.ctl_listen_fd);
  max_fd = MAX(max_fd, private.ctl_listen_fd);
  max_fd = MAX(max_fd,  public.data_fd);
  max_fd = MAX(max_fd, private.data_fd);

  publicturn = 1;
  done = 0;

  while(!done)
  {
    fd_set temp;
    struct timeval tv, *waittime;
    char buf[128];

    waittime=NULL;
    if(public.nh_input ||
       private.nh_input) {
      tv.tv_sec  = 0;
      tv.tv_usec = 500000;
      waittime = &tv;
    }

    temp = perm_fds;

    if(debug > 1) {
	    printf("invoking select with %s %s %s",
		   waittime ? "waittime" : "no wait",
		   public.nh_input ?  "public"  : "no-public",
		   private.nh_input ? "private" : "no-priv");
	    fflush(stdout);
    }

    n = select(max_fd + 1, &temp, NULL, NULL, waittime);
    
    if(debug > 1) {
	    printf(" -> %d left %lu\n", n, tv.tv_usec);
    }

    if(n < 0){
      perror("select");
      done = 1;
    }
    if(waittime && tv.tv_usec == 0) {
      struct nethub *nh;

      /* timeout */
      if(publicturn) {
	nh = &public;
      } else {
	nh = &private;
      }

      if(nh->nh_input) {
	struct pcap_pkthdr ph;
	const u_char *packet;

	memset(&ph, 0, sizeof(ph));
	
	packet = pcap_next(nh->nh_input, &ph);
	if(packet == NULL) {
		nh->nh_input=NULL;
	} else {
	  printf("%8s: inserting packet of len %d\n", nh->nh_name, ph.len);
	  forward_data(nh, (struct packet *)packet, ph.len);
	}
      }

      publicturn = !publicturn;
      
      if(public.nh_input  == NULL &&
	 private.nh_input == NULL &&
	 exitonempty) {
	done=1;
      }
    }

    if(n > 0) {
      if(FD_ISSET(0, &temp)){
	n = read(0, buf, sizeof(buf));
	if(n < 0){
	  perror("Reading from stdin");
	  break;
	}
	else if(n == 0){
	  printf("EOF on stdin, cleaning up and exiting\n");
	  break;
	}
	continue;
      }
      else if(FD_ISSET(public.ctl_listen_fd, &temp)){
	accept_connection(&public);
	FD_CLR(public.ctl_listen_fd, &temp);
      }
      else if(FD_ISSET(private.ctl_listen_fd, &temp)){
	accept_connection(&private);
	FD_CLR(private.ctl_listen_fd, &temp);
      }
      
      if(FD_ISSET(public.data_fd, &temp)){
	handle_data(&public);
	FD_CLR(public.data_fd, &temp);
      } else if(FD_ISSET(private.data_fd, &temp)){
	handle_data(&private);
	FD_CLR(private.data_fd, &temp);
      }

      handle_connections(&public, &temp, max_fd + 1);
      handle_connections(&private,&temp, max_fd + 1);
    }
  }
  cleanup(&public);
  cleanup(&private);
  return 0;
}

/*
 * $Log: uml_netjig.c,v $
 * Revision 1.8  2002/01/21 01:08:41  mcr
 * 	do not die if -t option is provided, but tcpdump compiled out.
 *
 * Revision 1.7  2002/01/12 04:01:36  mcr
 * 	another #ifdef NETDISSET for tcpdump_print access.
 *
 * Revision 1.6  2002/01/12 03:40:56  mcr
 * 	missing #ifdef for on NETDISSECT call.
 *
 * Revision 1.5  2002/01/12 02:52:46  mcr
 * 	added --debug option to replace #if 0.
 *
 * Revision 1.4  2001/10/23 16:34:12  mcr
 * 	use "progname" instead of "prog"
 * 	fixed public/private confused variables in printf().
 * 	fixed bug in termination logic.
 *
 * Revision 1.3  2001/10/14 00:27:10  mcr
 * 	added code to play pcap files to both public and private sides.
 * 	updated usage.
 *
 * Revision 1.2  2001/10/12 20:54:02  mcr
 * 	documented environment variables
 * 	added arp replies
 * 	added --help and fixed Usage().
 *
 * Revision 1.1  2001/10/08 22:54:05  mcr
 * 	uml_net program that handles two interfaces.
 * 	no support for pcap yet.
 *
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 2
 * End:
 *
 */
