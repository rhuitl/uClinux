/* makeiplist.c */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define DHCPD_IPLIST_FILE		"/home/matthewr/dhcpd/dhcpd/dhcpd.iplist"


/* local prototype */
int addAddress(char *ip);


int main() {
	printf("Make IP List Utility (for the Lineo DHCP server)\n");

	addAddress("192.168.111.33");
	addAddress("192.168.111.34");
	addAddress("192.168.111.35");
	addAddress("192.168.111.36");

	return 0;
}


int addAddress(char *ip) {
	FILE *in;
	struct in_addr inp;
	
	printf("adding: %s\n", ip);

	inet_aton(ip, &inp);
	in = fopen(DHCPD_IPLIST_FILE, "a");
	if(in == NULL)
		return -1;
	fwrite(&inp.s_addr, sizeof(u_int32_t), 1, in);
	fclose(in);
	
	return 0;
}


