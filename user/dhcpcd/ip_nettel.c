/*
 * ip_nettel.c
 */

#ifdef CONFIG_NETtel

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <config/autoconf.h>
#include "error-handler.h"
#include "ip_nettel.h"

#define MAX_CONFIG_LINE_SIZE	128

/* local prototypes */
int writeConfig(char *filename, char *keyword, char *value);
void launch_script(char *filename);

/* write the IP address to /etc/config/config so the user can tell what
 * IP address the NETtel got. 
 *
 * Secondly, launch dhcpcd-change, but only if it is not a DISKTEL
 */
int ipfwadm_rules(char *ifname, u_int32_t yiaddr)
{
	char buf[32];
	FILE *in;
	pid_t pid;
	char tmp[MAX_CONFIG_LINE_SIZE];
	struct in_addr inp;
	struct stat st;
	
	inp.s_addr = yiaddr;

	/* No need to write this config to flash because it is dynamic
	 * information. */
	sprintf(buf, "ip%s\0", ifname);
	writeConfig("/etc/config/config", buf, (char *) inet_ntoa(inp));

#ifndef CONFIG_DEFAULTS_LINEO_DISKTEL
	if (stat("/etc/config/dhcpcd-change", &st) == 0) {
		launch_script("/etc/config/dhcpcd-change");
	} else {
		launch_script("/etc/config/ipfwrules");
	}
#endif

	return 0;
}


int writeConfig(char *filename, char *keyword, char *value)
{
	FILE *in;
	FILE *out;
	
	char line_buffer[64];
	char tmp[64];

	in = fopen(filename, "r");
	out = fopen("/etc/config/tmp", "w");
	
	while((fgets(line_buffer, 63, in)) != NULL) {
		if(sscanf(line_buffer, "%s", tmp) > 0) {
			if(!strcmp(tmp, keyword)) {
				/* don't write this line to the tmp file as we
				* are going to replace it later */
			} else {
				fputs(line_buffer, out);
			}
		}
	}	
	fclose(in);
	
	sprintf(tmp, "%s %s\n\0", keyword, value);
	fputs(tmp, out);
	fclose(out);

	rename("/etc/config/tmp", filename);
	
	return 0;
}


void launch_script(char *filename)
{
        char *argv[3];
        int s, argc = 0;
        pid_t pid;

        if((pid = vfork()) == 0) {
                argv[argc++] = "/bin/sh";
                argv[argc++] = filename;
                argv[argc] = NULL;
                execvp("/bin/sh", argv);
                exit(0);
        } else if (pid > 0) {
                waitpid(pid, &s, 0);
        }
}


#endif /* CONFIG_NETtel */
