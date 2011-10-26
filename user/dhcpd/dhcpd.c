/* dhcpd.c
 *
 * Lineo DHCP Server
 * Copyright (C) 1999 Matthew Ramsay <matthewr@lineo.com>
 *			Chris Trew <ctrew@lineo.com>
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
 */

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "debug.h"
#include "dhcpd.h"
#include "arpping.h"
#include "socket.h"
#include "options.h"
#include "files.h"
#include "nettel.h"


/* prototypes */
int log_pid();
int getPacket(struct dhcpMessage *packet, int server_socket);
int sendOffer(int client_socket, struct dhcpMessage *oldpacket);
int sendNAK(int client_socket, struct dhcpMessage *oldpacket);
int sendACK(int client_socket, struct dhcpMessage *oldpacket);
u_int32_t findAddr(u_int8_t *chaddr, u_int32_t xid);
int test_ip(u_int32_t ipaddr);
u_int32_t freeIPAddresses(u_int32_t leased[],int num_leased);


/* globals */
struct dhcpOfferedAddr offeredAddr[MAX_SIMUL_CLIENTS];
int offer_num = 0; /* how many offers we are currently serving */
unsigned char server_ipaddr[4];

char *interface_name = "eth0";
unsigned char	interface_hwaddr[6];

int main() {
	int server_socket;
	int client_socket;
	int bytes;
	struct dhcpMessage packet;
	unsigned char *state, *hw_addr;
	unsigned char *server_id;
	int search_result;
	
	/* server ip addr */
	int fd = -1;
	struct ifreq ifr;
	struct sockaddr_in *sin;

	/* by default 10.10.10.10 -- server id */
	server_ipaddr[0] = 0xA;
	server_ipaddr[1] = 0xA;
	server_ipaddr[2] = 0xA;
	server_ipaddr[3] = 0xA;

	openlog("dhcpd", 0, 0);
	syslog(LOG_INFO, "Lineo DHCP Server (v%s) started", VERSION);
	log_pid();
	
	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
		strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);
		ifr.ifr_addr.sa_family = AF_INET;
		if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
			sin = (struct sockaddr_in *)&ifr.ifr_addr;
#if DEBUG
			syslog(LOG_INFO, "%s (server_ip) = %s",
					interface_name,
					inet_ntoa(sin->sin_addr));
#endif
			memcpy(server_ipaddr, &sin->sin_addr, 4);
		}
		strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
			memcpy(interface_hwaddr, &ifr.ifr_hwaddr.sa_data,
					sizeof(interface_hwaddr));
			syslog(LOG_INFO, "%s (hwaddr) = %x:%x:%x:%x:%x:%x",
					interface_name,
					interface_hwaddr[0],
					interface_hwaddr[1],
					interface_hwaddr[2],
					interface_hwaddr[3],
					interface_hwaddr[4],
					interface_hwaddr[5]);
		}
		close(fd);
	}

	while(1) { /* loop until universe collapses */
		server_socket = serverSocket(LISTEN_PORT, interface_name);
		if(server_socket == -1) {
			syslog(LOG_ERR, "couldn't create server socket -- au revoir");
			exit(0);
		}


		bytes = getPacket(&packet, server_socket); /* this waits for a packet - idle */
		close(server_socket);
		if(bytes < 0)
			continue;

#ifdef CONFIG_NETtel
/*******************************************************************************************/
		/* Now check to see if the request came from this NETtel.
		 * if so we wish to ignore its cries for an address */
		if((state = getOption(packet.options, DHCP_CLIENT_ID)) == NULL) {
#if DEBUG
			syslog(LOG_ERR, "couldnt get option from packet (CLIENT_ID) -- ignoring");
			syslog(LOG_ERR, "maybe RedHat pump is the client.. -- ignore missing CLIENT_ID");
#endif
		} else {
		
			state++; /* move pointer up as state[0] == ARPHRD_ETHER == 0x01 */
			hw_addr = (unsigned char *) (0xf0006000);
	
			/* state should now be pointing to the  hardware address as will
			 * hw_addr which points to a memory location inside the nettel */
#if DEBUG_2
			syslog(LOG_INFO, "state = %02x%02x%02x%02x%02x%02x",state[0],state[1],state[2],state[3],state[4],state[5]);
			syslog(LOG_INFO, "hw1 = %02x%02x%02x%02x%02x%02x",hw_addr[0],hw_addr[1],hw_addr[2],hw_addr[3],hw_addr[4],hw_addr[5]);
			syslog(LOG_INFO, "hw2 = %02x%02x%02x%02x%02x%02x",hw_addr[6],hw_addr[7],hw_addr[8],hw_addr[9],hw_addr[10],hw_addr[11]);
#endif		
			if(memcmp(hw_addr,state,6) == 0) {
#if DEBUG
				syslog(LOG_INFO, "not responding to my other half self");
#endif
				continue; /* skip everything and listen to another request */
			} else if(memcmp(hw_addr+6,state, 6) == 0) {
#if DEBUG
				syslog(LOG_INFO, "not responding to my other half self");
#endif
				continue; /* skip everything and listen to another request */
			}
		}
/*******************************************************************************************/
#endif
	
		if((state = getOption(packet.options, DHCP_MESSAGE_TYPE)) == NULL) {
#if DEBUG
			syslog(LOG_ERR, "couldnt get option from packet (MSG_TYPE) -- ignoring");
#endif
			continue;
		}
		
#ifdef CONFIG_NETtel
		/* 1. why don't we add a 'route add -host allones ethX' here as
		 *		an experiment.
		 * 2. we should lock the DHCP client from working until route_del_host()
		 */
		route_add_host(ADD);
#endif
		
		if((client_socket = clientSocket(LISTEN_PORT, SEND_PORT, interface_name)) == -1) {
			syslog(LOG_ERR, "couldn't create client socket -- i'll try again");
			continue;
		}

		switch(state[0]) {
		case DHCPDISCOVER:
#if DEBUG_2
			syslog(LOG_INFO,"received DISCOVER");
#endif
			if(sendOffer(client_socket, &packet) == -1) {
				syslog(LOG_ERR, "send OFFER failed -- ignoring");
				close(client_socket);
				continue; /* error occoured */
			}
			break;
			
		case DHCPREQUEST:
#if DEBUG_2
			syslog(LOG_INFO,"received REQUEST");
#endif
			server_id = getOption(packet.options, 0x36);
			if(server_id == NULL) {
#if DEBUG_2
				syslog(LOG_INFO, "get option on 0x36 failed! NAKing");
#endif
				sendNAK(client_socket, &packet);
				/* Let's send an offer as well */
				if(sendOffer(client_socket, &packet) == -1) {
					syslog(LOG_ERR, "send OFFER failed -- ignoring");
					close(client_socket);
					continue; /* error occoured */
				}
			} else {
#if DEBUG_2
				syslog(LOG_INFO, "server_id = %02x%02x%02x%02x", server_id[0], server_id[1],
						server_id[2], server_id[3]);
#endif
				if(memcmp(server_id, server_ipaddr, 4) == 0) {
					if (sendACK(client_socket, &packet) == -1)
						sendNAK(client_socket, &packet);
				} else {
					sendNAK(client_socket, &packet);
				}
			}
			break;
			
		default:
			syslog(LOG_WARNING, "unsupported DHCP message (%02x) -- ignoring",
					state[0]);
			break;
		}
		
		close(client_socket);
#ifdef CONFIG_NETtel
		route_add_host(DEL); /* what the hell is this */
#endif
	}

	/* should never executes */
	syslog(LOG_ERR, "exit");
	closelog();
	return 0;
}


int log_pid() {
	FILE	*f;
	pid_t pid;
	char *pidfile = PID_FILE;

	pid = getpid();
	if((f = fopen(pidfile, "w")) == NULL)
		return -1;
	fprintf(f, "%d\n", pid);
	fclose(f);
}


int getPacket(struct dhcpMessage *packet, int server_socket) {
	char buf[sizeof(struct dhcpMessage)];
	u_int32_t magic;
	int bytes;

#if DEBUG_2
	syslog(LOG_INFO, "listening for any DHCP messages on network...");
#endif
	memset(buf, 0, sizeof(buf));
	bytes = read(server_socket, (char *)buf, sizeof(buf));
	if(bytes < 0) {
#if DEBUG
		syslog(LOG_INFO, "couldn't read on server socket -- ignoring");
#endif
		return -1;
	}

	memcpy(packet, buf, sizeof(buf));
	memcpy(&magic, &packet->cookie, 4);
	if(htonl(magic) != MAGIC) {
		syslog(LOG_ERR, "client sent bogus message -- ignoring");
		return -1;
	}
#if DEBUG_2
	syslog(LOG_INFO, "oooooh!!! got some!");
#endif
	return bytes;
}


/* send a DHCP OFFER to a DHCP DISCOVER */
int sendOffer(int client_socket, struct dhcpMessage *oldpacket) {
	FILE *in;
	struct dhcpMessage packet;
	char buf[sizeof(struct dhcpMessage)];
	int bytes;
	int n,k;
	int address_used = FALSE;
	int found_one = FALSE;
	char tmp[32];
	struct in_addr inp;

	memset(&packet, 0, sizeof(packet));
	
	packet.op = BOOTREPLY;
	packet.htype = ETH_10MB;
	packet.hlen = ETH_10MB_LEN;
	packet.xid = oldpacket->xid;
	if((packet.yiaddr = findAddr(oldpacket->chaddr, oldpacket->xid)) == 0) {
		syslog(LOG_WARNING, "no IP addresses to give -- OFFER abandoned");
		return -1;
	}
	
	memcpy(&packet.chaddr, oldpacket->chaddr, 16);
	memcpy(&packet.cookie, "\x63\x82\x53\x63", 4);
	memcpy(&packet.options, "\xff", 1);
	
	addOption(packet.options, 0x35, 0x01, "\x02");
	addOption(packet.options, 0x36, 0x04, server_ipaddr);

	/* lease time */
	addOption(packet.options, 0x33, 0x04, LEASE_TIME);
	
	/* subnet */
	if((search_config_file(DHCPD_CONF_FILE, "subnet", tmp)) == 1) {
		inet_aton(tmp, &inp);
		addOption(packet.options, 0x01, 0x04, (char *)&inp.s_addr);
	}

	/* gateway */
	if((search_config_file(DHCPD_CONF_FILE, "router", tmp)) == 1) {
		inet_aton(tmp, &inp);
		addOption(packet.options, 0x03, 0x04, (char *)&inp.s_addr);
	}
			
	memcpy(buf, &packet, sizeof(packet));

#if DEBUG_2
	syslog(LOG_INFO, "sending OFFER");
#endif
	bytes = send(client_socket, buf, sizeof(buf), 0);
	if(bytes == -1) {
#if DEBUG
		syslog(LOG_ERR, "couldn't write to client_socket -- OFFER abandoned");
#endif
		return -1;
	}
	return 0;
}


int sendNAK(int client_socket, struct dhcpMessage *oldpacket) {
	struct dhcpMessage packet;
	char buf[sizeof(struct dhcpMessage)];
	int bytes;

	memset(&packet, 0, sizeof(packet));
	
	packet.op = BOOTREPLY;
	packet.htype = ETH_10MB;
	packet.hlen = ETH_10MB_LEN;
	packet.xid = oldpacket->xid;
	memcpy(&packet.chaddr, oldpacket->chaddr, 16);
	memcpy(&packet.cookie, "\x63\x82\x53\x63", 4);
	memcpy(&packet.options, "\xff", 1);
	/* options should look like this:
	* 0x350106 -- NAK 
	* 0x3604serverid - server id */
	addOption(packet.options, 0x35, 0x01, "\x06");
	addOption(packet.options, 0x36, 0x04, server_ipaddr);
	
	memcpy(buf, &packet, sizeof(packet));
#if DEBUG_2
	syslog(LOG_INFO, "sending NAK");
#endif
	bytes = send(client_socket, buf, sizeof(buf), 0);
	
	if(bytes == -1) {
#if DEBUG
		syslog(LOG_ERR, "error writing to client -- NAK abandoned");
#endif
		return -1;
	}
	return 0;
}


int sendACK(int client_socket, struct dhcpMessage *oldpacket) {
	struct dhcpMessage packet;
	char buf[sizeof(struct dhcpMessage)];
	int bytes;
	int k;
	char tmp[96];
	char tmp1[32];
	char tmp2[32];
	char tmp3[32];
	struct in_addr inp;
	struct in_addr inp1;
	struct in_addr inp2;
	struct in_addr inp3;
	int result = FALSE;
	int num;

	memset(&packet, 0, sizeof(packet));
	
	packet.op = BOOTREPLY;
	packet.htype = ETH_10MB;
	packet.hlen = ETH_10MB_LEN;
	packet.xid = oldpacket->xid;
	packet.ciaddr = oldpacket->ciaddr;
	memcpy(&packet.chaddr, oldpacket->chaddr, 16);
	memcpy(&packet.chaddr, oldpacket->chaddr, 16);
	memcpy(&packet.cookie, "\x63\x82\x53\x63", 4);
	memcpy(&packet.options, "\xff", 1);

	/* loop thru offeredAddr to find which addr we
	 * offered this client */
#if DEBUG_2
	syslog(LOG_INFO, "cycling thru offered array of size %d", offer_num);
#endif
	for(k=0;k<offer_num;k++) { /* cycle through the offered array */
		if(memcmp(offeredAddr[k].chaddr,packet.chaddr, 16) == 0) {
#if DEBUG_2
			syslog(LOG_INFO, "chaddr matches what I have in my internel offer array");
#endif
			packet.yiaddr = offeredAddr[k].yiaddr;
			inp.s_addr = packet.yiaddr;
#if DEBUG_2
			syslog(LOG_INFO,"i'll attempt to ACK with ip_addr %s", inet_ntoa(inp));
#else
			syslog(LOG_INFO,"serving %s", inet_ntoa(inp));
#endif
			offeredAddr[k].yiaddr = offeredAddr[offer_num-1].yiaddr;			
			memcpy(offeredAddr[k].chaddr, offeredAddr[offer_num-1].chaddr, 16);
			offer_num--;
			result = TRUE;
			break;
		}
	}
	
	if (result != TRUE) { /* if we cant find it in the offered array somthing has gone wrong */ 
		syslog(LOG_ERR, "couldn't find in offer array -- ACK abandoned");
		return -1;
	}
	
	/* options should look like this:
	* 0x350106 -- NAK 
	* 0x3604 serverid - server id */
	addOption(packet.options, 0x35, 0x01, "\x05");
	addOption(packet.options, 0x36, 0x04, server_ipaddr);
	addOption(packet.options, 0x33, 0x04, LEASE_TIME);

	/* subnet */
	if((search_config_file(DHCPD_CONF_FILE, "subnet", tmp)) == 1) {
		inet_aton(tmp, &inp);
		addOption(packet.options, 0x01, 0x04, (char *)&inp.s_addr);
	}
	
	/* gateway */
	if((search_config_file(DHCPD_CONF_FILE, "router", tmp)) == 1) {
		inet_aton(tmp, &inp);
		addOption(packet.options, 0x03, 0x04, (char *)&inp.s_addr);
	}

	/* DNS */
#ifdef CONFIG_NETtel
	if((search_config_file(DHCPD_CONF_FILE,"dns", tmp)) == 1) {
	        inet_aton(tmp, &inp1);
		num = 1;
	} else 
		num = get_multiple_entries("/etc/config/resolv.conf",
			    "nameserver", tmp1, tmp2, tmp3);
#else
	num = get_multiple_entries("/etc/resolv.conf", "nameserver",
			tmp1, tmp2, tmp3);
#endif
	if(num>0) {
		inet_aton(tmp1, &inp1);
		if(num>1) {
			inet_aton(tmp2, &inp2);
			if(num>2) {
				inet_aton(tmp3, &inp3);
			}
		}
		if(num == 1) {
			add_multiple_option(packet.options, 0x06, 0x04, (char *)&inp1.s_addr, NULL, NULL);
		} else if(num == 2) {
			add_multiple_option(packet.options, 0x06, 0x08, (char *)&inp1.s_addr, (char *)&inp2.s_addr, NULL);
		} else if (num == 3) {
			add_multiple_option(packet.options, 0x06, 0x0c, (char *)&inp1.s_addr, (char *)&inp2.s_addr, (char *)&inp3.s_addr);
		}
	}
	
	/* WINS */
	if((search_config_file(DHCPD_CONF_FILE, "wins", tmp)) == 1) {
		inet_aton(tmp, &inp);
		addOption(packet.options, 0x2C, 0x04, (char *)&inp.s_addr);
	}
	
	memcpy(buf, &packet, sizeof(packet));
#if DEBUG_2
	syslog(LOG_INFO, "sending ACK");
#endif
	bytes = send(client_socket, buf, sizeof(buf), 0);
	
	if(bytes == -1) {
#if DEBUG
		syslog(LOG_ERR, "error writing to client_socket -- ACK abandoned");
#endif
		return -1;
	}

	/* write new ip to lease section of config file
	 * check that we dont write a lease that is already in the
	 * lease file (ie. reusing address since MAC is the same 
	 * if it came from the lease file already dont re add it */
	if(check_if_already_leased(packet.yiaddr, packet.chaddr) == 0) {
		addLeased(packet.yiaddr, packet.chaddr);
	}

#ifdef CONFIG_NETtel
	if(commitChanges() == -1)
		return -1;
#endif
	return 0;
}


u_int32_t findAddr(u_int8_t *chaddr, u_int32_t xid) {
	u_int32_t yiaddr = 0;
	u_int32_t iplist[MAX_IP_ADDR];
	u_int32_t leased[MAX_IP_ADDR];
	FILE *in = NULL;
	int n = 0;
	int k,i;
	size_t items; /* return value for fread */
	int num_ip_addr;
	int num_leased;
	u_int8_t mac_addr[16];
	u_int32_t ip_addr;
	int ip_leased = FALSE; /* is the addressed leased? */
	int already_in_offered = FALSE; 
	int offered_already = FALSE; /* check if the ip addresses in lease haven't been offered to someone else */
	int j;
	
	/* see if this chaddr is in the offered pool first */
	/* don't add this addr to offeredAddr if chaddr already in there! */
	/* win95 has a bad habbit of changing xid's halfway thru a conversation */
	for(n=0;n<offer_num;n++) {
		if(memcmp(offeredAddr[n].chaddr,chaddr,16) == 0) {
#if DEBUG_2			
			syslog(LOG_INFO, "chaddr already in offer array");
#endif			
			already_in_offered = TRUE;
			break;
		}
	}

	if (already_in_offered == TRUE && offeredAddr[n].yiaddr != 0) {
#if DEBUG_2
		syslog(LOG_INFO, "i've already offered you an address -- have it again (%x)", offeredAddr[n].yiaddr);
#endif
		return offeredAddr[n].yiaddr;
	} else {
#if DEBUG_2
		syslog(LOG_INFO, "searching for new address for new client");
#endif
	}
		
	/* open up dhcpd.iplist */
	if((in = fopen(DHCPD_IPLIST_FILE, "r")) == NULL) {
		syslog(LOG_ERR, "%s not found -- no IP pool to draw from", DHCPD_IPLIST_FILE);
		return -1;
	}
	
	/* Read in all the values into the iplist Array*/
	while(TRUE) {
		items = fread(&iplist[n++], sizeof(u_int32_t), 1, in);
		if(items < 1)
			break;
	}
	fclose(in);

	num_ip_addr = n-1;
		
	if((in = fopen(DHCPD_LEASES_FILE, "r")) == NULL) {
#if DEBUG_2
		syslog(LOG_WARNING, "dhcpd.leases not found -- no leases");
#endif
	}
	
	n=0;
	/* Read in the mac - IP pair from the leases file */
	while(TRUE) {
		if(in == NULL)
			break;
		items = fread(&mac_addr, sizeof(mac_addr), 1, in);
		if(items < 1)
			break;
		items = fread(&ip_addr, sizeof(ip_addr), 1, in);
		if(items < 1)
			break;
#if DEBUG_2
			syslog(LOG_INFO,"file yielded valid MAC/IP pair - ip_addr = %x", ip_addr);
			print_chaddr(mac_addr,"MAC");
			print_chaddr(chaddr,"CDR");
#endif

			
		/* Let's check that the ip addresses in lease haven't been offered to someone else */	
		offered_already = FALSE;
		for(j=0;j<offer_num;j++) {

			if (ip_addr==offeredAddr[j].yiaddr) {

										/* the address has already been offered */
#if DEBUG_2		
			syslog(LOG_INFO, "address already offered - %x from offeredAddr[]",offeredAddr[j].yiaddr);
#endif
				offered_already = TRUE;
			}
		}	

		if((memcmp(mac_addr, chaddr, sizeof(mac_addr)) == 0) && (offered_already == FALSE)){
#if DEBUG_2
			syslog(LOG_INFO, "hey! i've seen you around before...");
#endif
			/* ooh! the connecting clients MAC address
			* is already in lease file!! let's offer him
			* the address he used last time */
#if DEBUG_2			
			syslog(LOG_INFO, "i found an address you've used before.. have it again");
#endif			
			
	
			memcpy(offeredAddr[offer_num].chaddr,chaddr,16);
			offeredAddr[offer_num].yiaddr = ip_addr;
			if(offer_num < MAX_SIMUL_CLIENTS)
				offer_num++;
			else {
				syslog(LOG_ERR, "Ahhh!! i'm not configured to handle that many simultaneous clients!!");
				syslog(LOG_ERR, "I'm resetteing my offer count and trying again");
				offer_num=0;
			}
			return ip_addr;
		} else { 
			/* Add it to the array for later comparison between available leases 
			 * and the ones that are already leased */
#if DEBUG_2
	syslog(LOG_INFO, "added lease to array");
#endif
			leased[n++] = ip_addr;
		}
	}
	if(in != NULL)
		fclose(in);
	
	num_leased = n;
		
	/* compare the leased addresses with the actual list and
	 * find the first free address */ 
	/* also check the offeredAddr array so we don't offer the same
	 * addr to simultaneously connecting clients */
	for(n=0;n<num_ip_addr;n++) {
		for(k=0;k<num_leased;k++) {
			if(iplist[n] == leased[k]) {
				/* address already leased */
#if DEBUG_2				
				syslog(LOG_INFO, "address %x is already leased... skipping", iplist[n]);
#endif				
				ip_leased = TRUE;
				break;
			}
		}
		if(ip_leased == FALSE) { /* if the ip wasnt leased */
			/* check that it is not in offered list */
			for(i=0;i<offer_num;i++) { /* cycle thru offered array */
				if(iplist[n] == offeredAddr[i].yiaddr) { /* already there.. hand it out again */
					if (memcmp(offeredAddr[i].chaddr,chaddr,16) == 0) {
#if DEBUG_2				
						syslog(LOG_INFO, "already in offered array.. have it again!");
#endif				
						break;
					}
#if DEBUG_2				
					syslog(LOG_INFO, "address already offered but not yet cleared..");
#endif				
					ip_leased = TRUE;
					break;
				}
			}
			
			if(ip_leased == FALSE) {
				/* Now we test to see if the address is actually currently taken 
				 * if it is we should also set it to leased in the leased file */
				if (test_ip(iplist[n]) == 0) {
					/* it passed the test you are free to have it */
#if DEBUG_2				
					syslog(LOG_INFO, "address arped and is free");
#endif				
					yiaddr = iplist[n]; /* after setting the yiaddr for testing later */
					break;/* breaks outer loop */
				}
#if DEBUG_2
				else {
					/* looks like that IP is taken */
						syslog(LOG_INFO, "free IP is not so free...");
				}
#endif
			} else {
#if DEBUG_2
				syslog(LOG_INFO, "sorry.. another simultaneous client has been offered this address..");
#endif
			}
		}
		ip_leased = FALSE;
	}
	
	/* If you wanted you could compare the num ip addresses leased (num_leased) to
	 * the total num ip addresses (num_ip_addr) and determine a ratio to start 
	 * freeing up ip addresses -- HERE */  
	
	if(yiaddr == 0) {
		/* no free ip addresses remain */
#if DEBUG_2
		syslog(LOG_INFO, "no free IP addresses found in pool -- attempting to free one");
#endif

		/* If the ip addresses are full then there is somthing wrong 
		 * It will only occour when a network card has been replaced on a machine thus
		 * is very rare or there are more machines than addresses which is stoopid that
		 * is why we should only check this when the list is full and a machine is 
		 * requesting an IP address.
		 * Also Arp.c should be checked to make sure all addresses are correct */
		if ((yiaddr = freeIPAddresses(leased,num_leased)) == 0) { /* No IP addresses could be freed */
#if DEBUG
			syslog(LOG_ERR, "couldn't free any IP addresses -- add more to pool");
#endif
		} else {
#if DEBUG
			syslog(LOG_INFO, "i found a freeable IP address.. let's use that");
#endif
		}
	} 
	
#if DEBUG_2	
	syslog(LOG_INFO, "the IP address i'll use is %x", yiaddr);
#endif	
	
	memcpy(offeredAddr[offer_num].chaddr,chaddr,16); /* cp chaddr to offered array */
	offeredAddr[offer_num].yiaddr = yiaddr;
	if(offer_num < MAX_SIMUL_CLIENTS)
		offer_num++;
	else {
		syslog(LOG_ERR, "Ahhh!! i'm not configured to handle that many simultaneous clients!!");
		syslog(LOG_ERR, "I'm resetteing my offer count and trying again");
		offer_num=0;
	}
	return yiaddr;
}


u_int32_t freeIPAddresses (u_int32_t leased[],int num_leased) {
		int i,j;
		int found;	
		
		for(i=0;i<num_leased;i++) {

			found = arpping(leased[i]);
			if (found == 1) { /* if free address */ 
				/* if it timed out without a response */
#if DEBUG_2
			syslog(LOG_INFO, "found == 1 arpping %x",leased[i]);
#endif
				/* Check that the ip hasn't been offered already */
				for(j=0;j<offer_num;j++) {
					if (leased[i]==offeredAddr[j].yiaddr) {
											/* the address has already been offered */
#if DEBUG_2		
			syslog(LOG_INFO, "address already offered - %x from offeredAddr[]",offeredAddr[j].yiaddr);
#endif
						return 0;
					}
				}	
#if DEBUG		
					syslog(LOG_INFO, "i found a spare address %x from leased[]",leased[i]);
#endif
				return(leased[i]);
				break;
			} else if (found == 0) { /* address used */
#if DEBUG_2		
				syslog(LOG_INFO, "address already active - %x from leased[]",leased[i]);
#endif
			} 
		}
		return 0; /* Address not found */
}


/* Tests a free ip to check that it is not actually leased if it is it will
 * add the lease to the lease file and return 1
 * ret:	0 on success (not leased to another party )
 *	1 on success (actually leased to another party but lease file successfully updated)
 *	-1 error */
int test_ip(u_int32_t ipaddr) {
	int found;  
	u_int8_t chaddr[16] = {0x00,0x00,0x00,0x00,
			   	0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,
		 	        0x00,0x00,0x00,0x00};

#if DEBUG_2		
	syslog(LOG_INFO, "pinging IP to see if leased");
#endif

	found = arpping(ipaddr);
	
#if DEBUG_2
	syslog(LOG_INFO, "arpping returned %d", found);
#endif
	
	if (found == 1) { /* if free address */ 
		/*if it timed out without a response*/
#if DEBUG_2		
		syslog(LOG_INFO, "IP is free to use");
#endif
		return 0;
	} else if (found == 0) { /* address is used */
#if DEBUG_2		
		syslog(LOG_INFO, "IP is NOT free to use");
#endif
	/* now go add it to the leased file. */
		if (addLeased(ipaddr, chaddr) == -1) {
			return 1;
		}
#if DEBUG_2		
		else {
			syslog(LOG_INFO, "IP address leased and HW is zerod");
		}
#endif
	}
	return -1;
}

