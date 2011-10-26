#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
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


int main (void) {
	FILE *in;
	u_int8_t mac_addr[16];
	u_int32_t ip_addr;
	size_t items; /* return value for fread */

	if ((in = fopen("/etc/config/dhcpd.leases", "r")) == NULL) {
		printf("dhcpd.leases not found -- can't offer an IP without a table to draw from!");
		return -1;
	}
	
	printf("Mac Address       IP-Address\n");
	
	while(1) {
	items = fread(&mac_addr, sizeof(mac_addr), 1, in);
	if(items < 1)
		break;
	items = fread(&ip_addr, sizeof(ip_addr), 1, in);
		if(items < 1)
		break;
	}
	printf("%02x:%02x:%02x:%02x:%02x:%02x %s",
		mac_addr[9],mac_addr[10],mac_addr[11],mac_addr[12],
		mac_addr[13],mac_addr[14],mac_addr[15]);
		
		
}
