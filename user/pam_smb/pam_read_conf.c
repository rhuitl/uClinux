#include <stdio.h>
#include <string.h>

#define CONFFILE "/etc/config/pam_smb.conf"

/***********************************************************************
	This file is (C) Dave Airlie 1997 ( David.Airlie@ul.ie ) 
	and is covered by the GPL provided in the COPYING FILE.
***********************************************************************/
int smb_readpamconf(char *smb_server, char *smb_server_addr, char *smb_backup, char *smb_backup_addr, char *smb_domain);

int smb_readpamconf(char *smb_server, char *smb_server_addr, char *smb_backup, char *smb_backup_addr, char *smb_domain)
{
	FILE *fl;
		
	int len;
	if (!(fl=fopen(CONFFILE,"r")))
	{
		return 1;
	}
	
	fgets(smb_domain, 50, fl); 
	len=strlen(smb_domain);
	smb_domain[len-1]='\0';
	/* Get the server_addr line. May have just the NETBIOS name, or the NETBIOS name and an address */
	char server_details[80];
	char *tok;
	
	fgets(server_details, 80, fl);
	tok = strtok(server_details, " ");
	if (!tok) return 1;
	strncpy(smb_server, tok, 50);
	tok = strtok(NULL, " ");
	if (tok) {
		strncpy(smb_server_addr, tok, 50);
	} else {
		smb_server_addr[0]='\0';
	}
	
	fgets(server_details, 80, fl);
	tok = strtok(server_details, " ");
	if (!tok) return 1;
	strncpy(smb_backup, tok, 50);
	tok = strtok(NULL, " ");
	if (tok) {
		strncpy(smb_backup_addr, tok, 50);
	} else {
		smb_backup_addr[0]='\0';
	}

	fclose(fl);
	return(0);
}

