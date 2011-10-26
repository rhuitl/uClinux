// $Id: ip-sentinel.c,v 1.32 2005/03/29 15:50:36 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003,2004,2005 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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
#include "wrappers.h"
#include "util.h"
#include "parameters.h"
#include "blacklist.h"
#include "antidos.h"
#include "arpmessage.h"
#include "ip-sentinel.h"
#include "worker.h"
#include "jobinfo.h"

#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <grp.h>

struct ether_addr	local_mac_address;
volatile sig_atomic_t	do_reload;

static void sigHup(int);

void
sigHup(int sig UNUSED)
{
  do_reload = 1;
  signal(SIGHUP, sigHup);
}

static void ALWAYSINLINE
adjustUserGroup(struct Arguments *arguments, uid_t *uid, gid_t *gid)
{
  struct passwd const *	pw_user;
  char *		err_ptr;

  assert(uid!=0 && gid!=0);
  
  *gid = static_cast(gid_t)(-1);
  *uid = strtol(arguments->user, &err_ptr, 0);
  if (arguments->user[0]!='\0' && *err_ptr=='\0') pw_user = getpwuid(*uid);
  else                                            pw_user = Egetpwnam(arguments->user);
  
  if (pw_user!=0) {
    *uid = pw_user->pw_uid;
    *gid = pw_user->pw_gid;
    if (arguments->chroot==0) arguments->chroot = pw_user->pw_dir;
  }

  if (arguments->group!=0) {
    *gid = strtol(arguments->group, &err_ptr, 0);
    if (arguments->group[0]=='\0' || *err_ptr!='\0')
      *gid = Egetgrnam(arguments->group)->gr_gid;
  }

  if (*gid==static_cast(gid_t)(-1)) {
    WRITE_MSGSTR(2, "Failed to determine gid; perhaps you should use the '-g' option. Aborting...\n");
    exit(1);
  }
}

static void //ALWAYSINLINE
daemonize(struct Arguments *arguments)
{
  int			err_fd, out_fd, pid_fd;
  int			aux;
  uid_t			uid;
  gid_t			gid;
  pid_t			daemon_pid;

  err_fd = Eopen(arguments->errfile, O_WRONLY|O_CREAT|O_APPEND|O_NONBLOCK, 0600);
  out_fd = Eopen(arguments->logfile, O_WRONLY|O_CREAT|O_APPEND|O_NONBLOCK, 0600);
  pid_fd = (!arguments->do_fork ? -1 :
	    Eopen(arguments->pidfile, O_WRONLY|O_CREAT|O_TRUNC, 0755));

  adjustUserGroup(arguments, &uid, &gid);
  
  if (arguments->chroot != 0) {
    Echdir(arguments->chroot);
    Echroot(arguments->chroot);
  }

  Esetgroups(1, &gid);
  Esetgid(gid);
  Esetuid(uid);

  Eclose(0);

  aux = Eopen(arguments->ipfile, O_RDONLY, 0);
  Eclose(aux);

  if (arguments->do_fork) daemon_pid = Efork();
  else                    daemon_pid = 0;

  switch (daemon_pid) {
    case 0	:  break;
    default	:
      writeUInt(pid_fd, daemon_pid);
      Ewrite  (pid_fd, "\n", 1);
      assert(daemon_pid!=-1);
      exit(0);
      break;
  }

  if (arguments->do_fork) Esetsid();

  Edup2(out_fd, 1);
  Edup2(err_fd, 2);

  if (pid_fd!=-1) Eclose(pid_fd);
  Eclose(out_fd);
  Eclose(err_fd);

  SETCLOEXEC(1);
  SETCLOEXEC(2);
}

inline static int ALWAYSINLINE
initIfaceInformation(int fd, char const *iface_name)
{
  struct ifreq		iface;
  int			ifidx;
  
  assert(iface_name!=0);
  memcpy(iface.ifr_name, iface_name, IFNAMSIZ);
  Eioctl(fd, SIOCGIFINDEX, &iface);
  if (iface.ifr_ifindex<0) {
    WRITE_MSGSTR(2, "No such interface '");
    WRITE_MSG   (2, iface_name);
    WRITE_MSGSTR(2, "'\n");
    exit(1);
  }

  ifidx = iface.ifr_ifindex; 
  Eioctl(fd, SIOCGIFHWADDR, &iface);
  switch (iface.ifr_hwaddr.sa_family) {
    case ARPHRD_ETHER   :
      memcpy(&local_mac_address, iface.ifr_hwaddr.sa_data, sizeof(local_mac_address));
      break;

    default             :
      WRITE_MSGSTR(2, "unsupported hardware-address (MAC) family of used interface\n");
      exit(1);
  }

  return ifidx;
}

static void ALWAYSINLINE
generateJobToIntruder(struct Worker *worker,
		      AntiDOS *anti_dos, BlackList const *blacklist,
		      ArpMessage const *const msg,
		      unsigned 
int *oversize_sleep)
{
  struct ether_addr const	*mac;
  int				arp_count;
  struct RequestInfo		job;
  struct in_addr const *	src_ip = reinterpret_cast(struct in_addr const *)(msg->data.arp_spa);

  struct BlackListQuery		query = {
    .ip  = reinterpret_cast(struct in_addr const *)(msg->data.arp_tpa),
    .mac = 0,
  };
  
  mac = BlackList_getMac(blacklist, &query);
  if (mac==0) return;
  
  assert(src_ip!=0);
  if (AntiDOS_isOversized(anti_dos)) {
    writeMsgTimestamp(2);
    WRITE_MSGSTR(2, ": Too much requests from too much IPs; last IP was ");
    writeIP     (2, *src_ip);
    WRITE_MSGSTR(2, "\n");
    
    sleep(*oversize_sleep);
    *oversize_sleep = MIN(*oversize_sleep+1, 10);

    return;
  }

  *oversize_sleep = 1;
  arp_count = AntiDOS_registerIP(anti_dos, *src_ip);

  if (isDOS(arp_count)) {
    writeMsgTimestamp(2);
    WRITE_MSGSTR(2, ": Too much requests from ");
    writeIP     (2, *src_ip);
    WRITE_MSGSTR(2, "; DOS-measurement was ");
    writeUInt   (2, arp_count);
    WRITE_MSGSTR(2, "\n");
    return;
  }

  memset(&job, 0, sizeof job);
  job.request      = msg->data;
  job.mac          = *mac;
  job.type         = jobDST;
  job.poison_mac.f = false;

  Worker_sendJob(worker, &job);
}


static void ALWAYSINLINE
generateJobFromIntruder(struct Worker *worker,
			AntiDOS *anti_dos, BlackList const *blacklist,
			ArpMessage const *const msg,
			unsigned int *oversize_sleep)
{
  struct ether_addr const	*mac;
  int				arp_count;
  struct RequestInfo		job;
  struct in_addr const *	dst_ip  = reinterpret_cast(struct in_addr const *)(msg->data.arp_tpa);

  struct BlackListQuery		query = {
    .ip  = reinterpret_cast(struct in_addr const *)(msg->data.arp_spa),
    .mac = reinterpret_cast(struct ether_addr const *)(msg->data.arp_sha),
  };
    
    // Ignore 0.0.0.0 since it is used for duplicate address detection and/or
    // by DHCPDISCOVER
  if (query.ip->s_addr==0) return;
  
  mac = BlackList_getMac(blacklist, &query);
  if (mac==0) return;
  
  assert(dst_ip!=0);
  if (AntiDOS_isOversized(anti_dos)) {
    writeMsgTimestamp(2);
    WRITE_MSGSTR(2, ": Too much requests from too much IPs; last IP was ");
    writeIP     (2, *dst_ip);
    WRITE_MSGSTR(2, "\n");
    
    sleep(*oversize_sleep);
    *oversize_sleep = MIN(*oversize_sleep+1, 10);
    return;
  }

  *oversize_sleep = 1;
  arp_count = AntiDOS_registerIP(anti_dos, *query.ip);

  if (isDOS(arp_count)) {
    writeMsgTimestamp(2);
    WRITE_MSGSTR(2, ": Too much requests from intruder ");
    writeIP     (2, *query.ip);
    WRITE_MSGSTR(2, "; DOS-measurement was ");
    writeUInt   (2, arp_count);
    WRITE_MSGSTR(2, ", current dst ");
    writeIP     (2, *dst_ip);
    WRITE_MSGSTR(2, "\n");
    return;
  }

  memset(&job, 0, sizeof job);
  job.request = msg->data;
  job.mac     = *mac;
  job.type    = jobSRC;

  if (query.poison_mac) {
    job.poison_mac.f = true;
    job.poison_mac.v = *query.poison_mac;
  }
  else
    job.poison_mac.f = false;

  Worker_sendJob(worker, &job);
}


static void NORETURN //ALWAYSINLINE
run(struct Worker *worker, struct Arguments const *args) 
{
  BlackList			cfg;
  AntiDOS			anti_dos;
  unsigned int			error_count = 0;
  struct sockaddr_ll		addr;
  socklen_t			from_len;
  char				buffer[4096];
  ArpMessage const * const	msg    = reinterpret_cast(ArpMessage const *)(buffer);
  unsigned int			oversize_sleep = 1;
  int				sock = worker->sock;

  memset(&addr, 0, sizeof(addr));
  
  BlackList_init(&cfg, args);
  AntiDOS_init(&anti_dos);

  while (true) {
    size_t			size;
    
    AntiDOS_update(&anti_dos);

    from_len = sizeof(addr);
    size     = TEMP_FAILURE_RETRY(recvfrom(sock, buffer, sizeof buffer, 0,
					   (struct sockaddr *)(&addr), &from_len));

    if (static_cast(ssize_t)(size)==-1) {
      ++error_count;
      if (error_count>MAX_ERRORS) {
	perror("recvfrom()");
	exit(1);
      }

      continue;
    }

    error_count = 0;

    if (ntohs(addr.sll_protocol)     !=ETHERTYPE_ARP) continue;
    if (ntohs(msg->data.ea_hdr.ar_op)!=ARPOP_REQUEST) continue;

    if (!do_reload) BlackList_softUpdate(&cfg);
    else {
      BlackList_update(&cfg);
      do_reload = false;
    }

    if (args->arp_dir & dirTO)
      generateJobToIntruder  (worker, &anti_dos, &cfg, msg, &oversize_sleep);

    if (args->arp_dir & dirFROM)
      generateJobFromIntruder(worker, &anti_dos, &cfg, msg, &oversize_sleep);
  }
}

inline static int ALWAYSINLINE
generateSocket(char const *iface, int *idx)
{
  int			sock = Esocket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  struct sockaddr_ll	addr;

  assert(iface!=0);
  assert(idx!=0);

  SETCLOEXEC(sock);
  *idx = initIfaceInformation(sock, iface);

  memset(&addr, 0, sizeof(addr));
  addr.sll_family   = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_ARP);
  addr.sll_ifindex  = *idx;
  
  (void)Ebind(sock, &addr, sizeof addr);

  return sock;
}

int
main(int argc, char *argv[])
{
  struct Arguments	arguments;
  int			sock;
  int			if_idx;
  struct Worker		worker;
  
  parseOptions(argc, argv, &arguments);

  sock   = generateSocket(arguments.iface, &if_idx);
  daemonize(&arguments);

  Arguments_fixupOptions(&arguments);
  
  Worker_init(&worker, &arguments, sock, if_idx);

  signal(SIGHUP,  sigHup);

  run(&worker, &arguments);
}
