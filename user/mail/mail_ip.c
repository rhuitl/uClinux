/* Used to mail a group of users the nettels new ip address */


#include <netdb.h>
#include <netinet/in.h>


#include "smtpmail.h"
#include "resolv.h"

#define VERSION "0.2.2"
#define MAX_CONFIG_LINE_SIZE 255
#define MAIL_IP_DEBUG 0
#define MASS_MAIL 1
#define MAIL_ADDRESS "moloth@hotmail.com"
//char* resolv (char* hostname);

SMTP smtp;

main() {
	char tmpstr[255];
	char value[20];
	struct in_addr ina;

	smtp_clear(&smtp);
		
	/* Subject Line --*/
#ifdef CONFIG_NETtel
	search_config_file("/etc/config/config","ipeth0",value);
	strcat(tmpstr,value);
#else
	strcpy(tmpstr,"Nettels IP = Omygosh! its hideous!");
#endif
	smtp.strSubject = tmpstr;
	
	/* Message      --*/
	smtp.strMessageBody = "Snarble";
		
	/* Sender Email --*/
	smtp.strSenderUserId = "Nettel <nettel@kma.com>";		//smtp.strSenderUserId = "padamo@worldnet.att.net";
	smtp.strFullSenderUserId = "";
	
	/*Destination ish */
	smtp.strFullDestUserIds = "";
	
	//CC addresses
	smtp.strCcUserIds = "";
	smtp.strCcUserIds = smtp_fill_in_addresses("");
	if (smtp.strCcUserIds == NULL) exit(-1);
	smtp.strFullCcUserIds = "";
	
	//BCC addresses
	smtp.strBccUserIds = "";
	smtp.strBccUserIds = smtp_fill_in_addresses("");
	if (smtp.strBccUserIds == NULL) exit(-1);
	smtp.strFullBccUserIds = "";
	
	smtp.strRplyPathUserId = "nettle@blowme.com";
	//this is who the return receipt goes back to
	smtp.strRrcptUserId = "";
	//override the name of the mailing function with this field
	smtp.strMailerName = "";
	//add a comment here if necessary
	smtp.strMsgComment = "";
	
#if MASS_MAIL
	
	printf("Starting Mass Mail\n");
	
	mass_mail(&smtp,"goober.mail");
	
#else /* Resolve the default address */
		
	//NOTE: these must be pointed into VARIABLE SPACE, otherwise you get memory faults!
	//Desitination addresses
	smtp.strDestUserIds = smtp_fill_in_addresses(MAIL_ADDRESS);
	if (smtp.strDestUserIds == NULL) exit(-1);

		if (resolv(&ina,MAIL_ADDRESS) != 0) {
		printf("Couldnt Resolve - quiting..");
		exit(1);
	}

	smtp.strSmtpServer = inet_ntoa(ina);

	smtp_print(&smtp);
	smtp_send_mail(&smtp,FALSE);	//show progress of sending process
	printf("-------------------------------------------------\n\r");

#endif
	
	free(smtp.strDestUserIds);
	free(smtp.strCcUserIds);
	free(smtp.strBccUserIds);
	printf("Finished.\n\r");

	
} //end proc main()

/*
 * search_config_file - (ripped from cgi database.c)
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
int search_config_file(char *filename, char *keyword, char *value) {
	FILE *in;
	int len;
	char buffer[MAX_CONFIG_LINE_SIZE], w[MAX_CONFIG_LINE_SIZE],
		v[MAX_CONFIG_LINE_SIZE];

	in = fopen(filename, "r");
	
	if(in == NULL) {
		/* Couldn't find config file, or permission denied */
		return -1;
	}
	
	while((fgets(buffer, MAX_CONFIG_LINE_SIZE - 1, in)) != NULL) {
		/* short-circuit comments */
		if(buffer[0] == '#')
			continue;

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
/*
char* resolv (char* hostname) {
	struct hostent* ptrhe;
	struct in_addr ina; 
	int i = 0;
	
#ifdef MAIL_IP_DEBUG	
	printf("Searching...\n");
#endif	
	if ((ptrhe = gethostbyname(hostname)) == NULL) {
#ifdef MAIL_IP_DEBUG		
		printf("Couldnt Resolve Hostname\n");
#endif		
		return NULL;
	}
#ifdef MAIL_IP_DEBUG	
	printf("*h_name = %s\n",ptrhe->h_name);
	while (ptrhe->h_aliases[i] != 0) {
		printf("*h_aliases[%d] = %s\n",i,ptrhe->h_aliases[i]);
		i++;
	}
	printf("*h_length = %d\n",ptrhe->h_length);
	i = 0;
	while (ptrhe->h_addr_list[i] != 0) {
		ina.s_addr = (int) ptrhe->h_addr_list[i];
		printf("*h_addr_list[%d] = %s\n",i,inet_ntoa(ina));
		i++;
	}
#endif		
	ina.s_addr = (int) ptrhe->h_addr;

#ifdef MAIL_IP_DEBUG	
	printf("*h_addr = %s\n",inet_ntoa(ina));
#endif	
	return inet_ntoa(ina);
}
*/
int mass_mail(SMTP * smtp,char *filename) {
	FILE *in;
	int len;
	struct in_addr ina;
	char buffer[MAX_CONFIG_LINE_SIZE];

	in = fopen(filename, "r");
	
	if(in == NULL) {
		/* Couldn't find config file, or permission denied */
		return -1;
	}
	
	while((fgets(buffer, MAX_CONFIG_LINE_SIZE - 1, in)) != NULL) {
		printf("Buffer = %s",buffer);
		/* short-circuit comments */
		if(buffer[0] == '#')
			continue;
		
		if (buffer[strlen(buffer)-1] == '\n') { /*strip any trailing \n's*/
			printf("Stripping \\n\n");
			buffer[strlen(buffer)-1] = '\0';
		}

		/* Gather different addresses to end the message to */
		if (resolv(&ina,buffer) != 0) {
			printf("Couldnt Resolve - Skipping\n");
			printf("-------------------------------------------------\n");
			continue;
		}
	


		//NOTE: these must be pointed into VARIABLE SPACE, otherwise you get memory faults!
		//Desitination addresses
		smtp->strDestUserIds = smtp_fill_in_addresses(buffer);
		if (smtp->strDestUserIds == NULL) {
			printf("Yukky error\n");
			exit(-1);
		}

			smtp->strSmtpServer = inet_ntoa(ina);
		smtp_print(smtp);
		smtp_send_mail(smtp,FALSE);	//show progress of sending process
		printf("-------------------------------------------------\n\r");
	}

	fclose(in);
	return 0;
}
