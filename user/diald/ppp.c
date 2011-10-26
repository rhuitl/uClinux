/*
 * ppp.c - ppp and pppd control.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

#if 0
#ifdef PPP_VERSION_2_2_0
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#else
#include <linux/ppp.h>
#endif
#else
#define PPPIOCGUNIT_2_1_2 0x5494
#define PPPIOCGUNIT_2_2_0 _IOR('t', 86, int)
#endif

/* internal flag to shortcut repeated calls to setaddr */
static int rx_count = -1;

#ifdef EMBED
#define	PPPD_MAXARGS	32
char *argv[PPPD_MAXARGS];
#endif

void ppp_start()
{
    int pgrpid, pid;
    char buf[24];

    link_iface = -1;
    rx_count = -1;
    /* Run pppd directly here and set up to wait for the iface */
#ifdef __uClinux__
    pid = link_pid = vfork();
#else
    pid = link_pid = fork();
#endif

    if (pid < 0) {
	syslog(LOG_ERR, "failed to fork pppd: %m");
	die(1);
    }

    if (pid == 0) {
#ifndef EMBED
	/* Naughty, naughty, should check NULL pointer here... */
	char **argv = (char **)malloc(sizeof(char *)*(pppd_argc+9));
#endif
	int i = 0, j;

#ifdef EMBED
	if (pppd_argc > PPPD_MAXARGS-1) {
	    syslog(LOG_ERR, "too many arguments %s: %d", PATH_PPPD, pppd_argc);
	    _exit(99);
	}
#endif
	argv[i++] = PATH_PPPD;
	argv[i++] = "-detach";
	if (modem) argv[i++] = "modem";
	if (crtscts) argv[i++] = "crtscts";
        argv[i++] = "mtu";
	sprintf(buf,"%d",mtu);
	argv[i++] = buf;
        argv[i++] = "mru";
	sprintf(buf,"%d",mru);
	argv[i++] = buf;
	if (netmask) {
	    argv[i++] = "netmask";
	    argv[i++] = netmask;
	}
	for (j = 0; j < pppd_argc; j++) {
	    argv[i++] = pppd_argv[j];
	}
	argv[i++] = 0;

	/* make sure pppd is the session leader and has the controlling
         * terminal so it gets the SIGHUP's
         */
	pgrpid = setsid();
        ioctl(modem_fd, TIOCSCTTY, 1);
	tcsetpgrp(modem_fd, pgrpid);

	setreuid(getuid(), getuid());
	setregid(getgid(), getgid());

	dup2(modem_fd, 0);
	dup2(modem_fd, 1);

	execv(PATH_PPPD,argv);
	syslog(LOG_ERR, "could not exec %s: %m",PATH_PPPD);
	_exit(99);
	/* NOTREACHED */
    }
    syslog(LOG_INFO,"Running pppd (pid = %d).",link_pid);
}

/*
 * SET_SA_FAMILY - set the sa_family field of a struct sockaddr,
 * if it exists.
 */

#define SET_SA_FAMILY(addr, family)                     \
    memset ((char *) &(addr), '\0', sizeof(addr));      \
    addr.sa_family = (family);

/*
 * Find the interface number of the ppp device that pppd opened up and
 * do any routing we might need to do.
 * If pppd has not yet opened the device, then return 0, else return 1.
 */

int ppp_set_addrs()
{
    ulong laddr = 0, raddr = 0;
    char sbuf[sizeof(PATH_IFCONFIG SL_DOWN) + 10];

    /* Try to get the interface number if we don't know it yet. */
    if (link_iface == -1) {
	 /* Try the pppd-2.2.0 ioctrl first,
	  * Try the pppd-2.1.2 ioctrl if that fails
	  */
   	 if (ioctl(modem_fd, PPPIOCGUNIT_2_2_0, &link_iface) == -1)
   	 	ioctl(modem_fd, PPPIOCGUNIT_2_1_2, &link_iface);
    }

    /* Ok then, see if pppd has upped the interface yet. */
    if (link_iface != -1) {
	struct ifreq   ifr; 

	SET_SA_FAMILY (ifr.ifr_addr,    AF_INET); 
	SET_SA_FAMILY (ifr.ifr_dstaddr, AF_INET); 
	SET_SA_FAMILY (ifr.ifr_netmask, AF_INET); 
	sprintf(ifr.ifr_name,"ppp%d",link_iface);
	if (ioctl(snoopfd, SIOCGIFFLAGS, (caddr_t) &ifr) == -1) {
	   syslog(LOG_ERR,"failed to read ppp interface status");
	   return 0;
	}
	if (!(ifr.ifr_flags & IFF_UP))
	    return 0;	/* interface is not up yet */

	if (route_wait) {
	    /* set the initial rx counter once the link is up */
	    if (rx_count == -1) rx_count = ppp_rx_count();

	    /* check if we got the routing packet yet */
	    if (ppp_rx_count() == rx_count) return 0;
	}

	/* Ok, the interface is up, grab the addresses. */
	if (ioctl(snoopfd, SIOCGIFADDR, (caddr_t) &ifr) == -1)
		syslog(LOG_ERR,"failed to get ppp local address: %m");
	else
       	    laddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

	if (ioctl(snoopfd, SIOCGIFDSTADDR, (caddr_t) &ifr) == -1) 
	   syslog(LOG_ERR,"failed to get ppp remote address: %m");
	else
	   raddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

 	/* Check the MTU, see if it matches what we asked for. If it
	 * doesn't warn the user and adjust the MTU setting.
	 * (NOTE: Adjusting the MTU setting may cause kernel nastyness...)
	 */
	if (ioctl(snoopfd, SIOCGIFMTU, (caddr_t) &ifr) == -1) {
	    syslog(LOG_ERR,"failed to get ppp mtu setting: %m");
	} else {
	    if (ifr.ifr_mtu != mtu) {
	        syslog(LOG_ERR,"PPP negotiated mtu of %d does not match requested setting %d.",ifr.ifr_mtu,mtu);
		syslog(LOG_ERR,"Attempting to auto adjust mtu.");
		syslog(LOG_ERR,"Restart diald with mtu set to %d to avoid errors.",ifr.ifr_mtu);
		mtu = ifr.ifr_mtu;
	        proxy_config(orig_local_ip,orig_remote_ip);
	    }
	}

	if (dynamic_addrs) {
	    /* only do the configuration in dynamic mode. */
	    struct in_addr addr;
	    addr.s_addr = raddr;
	    if (remote_ip)
		free(remote_ip);
	    remote_ip = strdup(inet_ntoa(addr));
	    addr.s_addr = laddr;
	    if (local_ip)
		free(local_ip);
	    local_ip = strdup(inet_ntoa(addr));
	    local_addr = laddr;
	    syslog(LOG_INFO,"New addresses: local %s, remote %s.",
		local_ip,remote_ip);
	    /* have to reset the proxy if we won't be rerouting... */
	    if (!do_reroute) {
		/* If we are rerouting, then we have a window without
		 * routes here. The proxy_config calls ifconfig, which
		 * clobbers all the routes.
		 */
	    	proxy_config(local_ip,remote_ip);
    		set_ptp("sl",proxy_iface,remote_ip,metric+1);
	        add_routes("sl",proxy_iface,local_ip,remote_ip,drmetric+1);
	    }
	}

	/* This is redundant in normal operation, but if we
	 * have to restart the link, then this is necessary...
	 */
	set_ptp("ppp",link_iface,remote_ip,metric);

	if (do_reroute)
	     add_routes("ppp",link_iface,local_ip,remote_ip,drmetric);

	snprintf(sbuf, sizeof(sbuf), PATH_IFCONFIG SL_DOWN, proxy_iface);
	system(sbuf);
	snprintf(sbuf, sizeof(sbuf), PATH_IFCONFIG SL_UP, proxy_iface);
	system(sbuf);

	return 1;
    }
    return 0;
}

int ppp_dead()
{
    /* pppd is way too enthusiastic about deleting routes it had
     * nothing to do with creating. Therefore, we have to reestablish
     * the proxy routes here, including the point to point route!
     */
    if (link_pid == 0)
	ppp_reroute();
    return (link_pid == 0);
}

int ppp_route_exists()
{
    char buf[128];
    int device = 0;
    int found = 0;
    FILE *fp;
    sprintf(buf,"%s -n",PATH_ROUTE);
    if ((fp = popen(buf,"r"))==NULL) {
        syslog(LOG_ERR,"Could not run command '%s': %m",buf);
	return 0;	/* assume half dead in this case... */
    }

    while (fgets(buf,128,fp)) {
	if (sscanf(buf,"%*s %*s %*s %*s %*s %*s %*s ppp%d",&device) == 1) {
	    if (device == link_iface) found = 1;
	}
    }
    fclose(fp);
    return found;
}

int ppp_rx_count()
{
    char buf[128];
    int packets = 0;
    FILE *fp;
    sprintf(buf,"%s ppp%d",PATH_IFCONFIG,link_iface);
    if ((fp = popen(buf,"r"))==NULL) {
        syslog(LOG_ERR,"Could not run command '%s': %m",buf);
	return 0;	/* assume half dead in this case... */
    }

    while (fgets(buf,128,fp)) {
	if (sscanf(buf," RX packets:%d",&packets) == 1) {
	    break;
	}
    }
    fclose(fp);
    return packets;
}

void ppp_stop()
{
    if (link_pid)
    	if (kill(link_pid,SIGINT) == -1 && errno == ESRCH)
	    link_pid = 0;
}

void ppp_reroute()
{
    /* Restore the original proxy routing */
    /* If there was a change in the proxy addresses
     * (i.e., we are running with -reroute), then
     * this will change introduce a window in which
     * we loose our routes. There does not seem to be a way
     * to avoid this. Sigh.
     */
    proxy_config(orig_local_ip,orig_remote_ip);
    set_ptp("sl",proxy_iface,orig_remote_ip,metric+1);
    add_routes("sl",proxy_iface,orig_local_ip,orig_remote_ip,drmetric+1);
    local_addr = inet_addr(orig_local_ip);
    /* If we did routing on the ppp link, remove it */
    if (do_reroute && link_iface != -1)
    	del_routes("ppp",link_iface,local_ip,remote_ip,drmetric);
    link_iface = -1;
}

void ppp_kill()
{
    if (link_pid)
    	if (kill(link_pid,SIGINT) == -1 && errno == ESRCH)
	    link_pid = 0;
}

void ppp_zombie()
{
    /* Either ppp became a zombie or we missed a SIGCHLD signal */

    sig_chld(SIGKILL);	/* try to reap the child */
    link_pid = 0;	/* just in case the reaping failed, forget zombie */
}
