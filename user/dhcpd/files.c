/* files.c -- DHCP server file manipulation */

#include "debug.h"
#include "dhcpd.h"

#include <stdio.h>
#include <syslog.h>


int get_multiple_entries(char *hay, char *needle, char *tmp1, char *tmp2, char *tmp3) {
        int num=0;
        FILE *in;
        int len;
        char buffer[32], w[32], v[32];

#if DEBUG_2
        syslog(LOG_ERR, "get_multiple_entries of %s from %s", needle, hay);
#endif
        if ((in = fopen(hay, "r")) == NULL) 
                return -1;

        while((fgets(buffer, 32 - 1, in)) != NULL) {
                /* check if it's what we want */
                if((sscanf(buffer, "%s %s", w, v) >= 1) && (strcmp(w, needle) == 0)) {
                        if(num == 0) {
                                strcpy(tmp1, v);
                                num++;
                        } else if(num == 1) {
                                strcpy(tmp2, v);
                                num++;
                        } else if(num == 2) {
                                strcpy(tmp3, v);
                                num++;
                        }
                }
        }
        fclose(in);
#if DEBUG
        syslog(LOG_INFO, "num=%d, tmp=%s, tmp2=%s, tmp3=%s", num, tmp1, tmp2, tmp3);
#endif
        return num;
}


/*
 *	opens up dhcpd.leases and looks for yiaddr.. returning
 *	1 if it finds it, 0 if not.  If we find the ip,  but the MAC
 *	is wrong we overwrite it
 */
int check_if_already_leased(u_int32_t yiaddr, u_int8_t *chaddr)
{
        u_int32_t lease;
        FILE *in;
        int n = 0;
        u_int8_t mac_addr[16];
        u_int32_t ip_addr;
        int num_ip_addr;
        size_t items; /* return value for fread */

        if((in = fopen(DHCPD_LEASES_FILE, "r+")) == NULL) {
#if DEBUG_2
			syslog(LOG_ERR, "dhcpd.leases not found -- no defined leases");
#endif
			return 0;
        }

        /* Read in the mac - IP pair from the leases file */
        while(TRUE) {
                items = fread(&mac_addr, sizeof(mac_addr), 1, in);
                if(items < 1)
                        break;
                items = fread(&ip_addr, sizeof(ip_addr), 1, in);
                if(items < 1)
                        break;
#if DEBUG_2
		syslog(LOG_INFO,"got a valid MAC/IP pair from dhcpd.leases");
		syslog(LOG_INFO,"ip_addr taken = %x", ip_addr);
#endif
                /* check if yiaddr matches ip_addr */
                if(ip_addr == yiaddr) {
						if (memcmp(chaddr, mac_addr, sizeof(mac_addr))) {
							if (fseek(in, -sizeof(ip_addr), SEEK_CUR))
								break;
							if (fseek(in, -sizeof(mac_addr), SEEK_CUR))
								break;
							if (fwrite(chaddr, 16, 1, in) != 1)
								break;
							if (fwrite(&yiaddr, sizeof(u_int32_t), 1, in) != 1)
								break;
						}
                        /* ip already in lease file */
                        fclose(in);
                        return 1;
                }
        }
        fclose(in);
        return 0;
}


int addLeased(u_int32_t yiaddr, u_int8_t *chaddr) {
        FILE *in;
#if DEBUG_2
        syslog(LOG_INFO,"Writing new lease to lease file (IP = %08x)",yiaddr);
        print_chaddr(chaddr,"MAC");
#endif
        if ((in = fopen(DHCPD_LEASES_FILE, "a")) == NULL)
                return -1;
        fwrite(chaddr, 16, 1, in);
        fwrite(&yiaddr, sizeof(u_int32_t), 1, in);
        fclose(in);

        return 0;
}


/* This function opens up the file specified 'filename' and searches
 * through the file for 'keyword'. If 'keyword' is found any string
 * following it is stored in 'value'.. If 'value' is NULL we assume
 * the function was called simply to determing if the keyword exists
 * in the file.
 *
 * args: filename (IN) - config filename
 *       keyword (IN) - word to search for in config file
 *       value (OUT) - value of keyword (if value not NULL)
 *
 * retn:        -1 on error,
 *                      0 if keyword not found,
 *                      1 if found
 */
int search_config_file(char *filename, char *keyword, char *value) {
        FILE *in;
        int len;
        char buffer[32], w[32], v[32];

        if ((in = fopen(filename, "r")) == NULL)
                return -1;

        while((fgets(buffer, 32 - 1, in)) != NULL) {
                /* check if it's what we want */
                if((sscanf(buffer, "%s %s", w, v) >= 1) && (strcmp(w, keyword) == 0)) {
                        /* found it :-) */
                        if(value == NULL) {
                                return 1;
                        } else {
                                strcpy(value, v);
                                fclose(in);
                                /* tell them we got it */
                                return 1;
                        }
                }
        }

        fclose(in);
        return 0;
}
