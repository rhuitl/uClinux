/*
 * radauth.c  1.00  01/13/01  mmiller@hick.org  Matt Miller
 *
 * PURPOSE
 *
 *   This application was developed in order to making testing of radius
 *   authentication slightly easier by enabling command line authentication.
 *   radauth was developed per RFC and therefore should be compatible with all
 *   RFC-compatible RADIUS servers.
 *
 * TESTED AGAINST
 *
 *   - ASCEND radiusd
 *   - cistron radiusd
 *
 * LICENSE
 *
 *   This application is freely distributable provided reference to the
 *   original creator is maintained in some form or another.  If there are any
 *   specific questions on whether or not the code may be used, please contact
 *   the author.
 *
 * MAINTAINED AT
 *
 *   http://www.afro-productions.com
 *   mmiller@hick.org
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "md5.h"

/*#define DEBUG 1*/

/*
 * Radius codes we'll need.
 */
#define CODE_ACCESS_REQUEST	1
#define CODE_ACCESS_ACCEPT	2
#define	CODE_ACCESS_REJECT	3

/*
 * Radius attribute types we'll need.
 */
#define	ATTR_TYPE_USER_NAME	1
#define ATTR_TYPE_USER_PASSWORD	2

/*
 * Data types for attributes
 */
#define DATATYPE_STRING		1
#define DATATYPE_ADDRESS	2
#define DATATYPE_INTEGER	3
#define DATATYPE_TIME		4

/*
 * radius's port (so is it 1812 or 1645?)
 * RFC says 1812, my server is 1645...
 */
#define RADIUS_PORT		1812

/* 
 * Request Authenticator defs
 */
#define REQ_AUTH_LENGTH		16

/*
 * default auth timeout (seconds)
 */
#define AUTH_TIMEOUT		30

typedef struct radius_attr_st {
	unsigned char attr_type;		/* 1 octet (written)	*/
	unsigned char attr_length;		/* 1 octet (written)	*/
	union {					/* all written		*/
		unsigned char string[254];	/* 254 octets		*/
		int address;			/* 4   octets		*/
		int integer;			/* 4   octets		*/
		int time;			/* 4   octets		*/
	} attr_data;

	unsigned int datatype;			/* 4   octets (IGNORED)	*/
	struct radius_attr_st *next;		/* 4   octets (IGNORED)	*/
} RADIUS_ATTR;					

typedef struct radius_header_st {
	unsigned char 	rad_code;		  /* 1  octet		*/
	unsigned char 	rad_id;			  /* 1  octet		*/
	short 		rad_length;		  /* 2  octets		*/
	unsigned char 	rad_auth[REQ_AUTH_LENGTH];/* 16 octets		*/
	RADIUS_ATTR	*rad_attr;		  /* variable octets	*/
} RADIUS_HEADER;

typedef struct global_st {
	char username[64];			/* username at suggested size			*/

	struct password_st {
		unsigned char pw_clear[128];	/* clear text password (128 = max)		*/
		unsigned char pw_hash[128];	/* hash password (128 = max)			*/
	} password;

	char sharedsecret[32];			/* shared secret				*/
	char radiusserver[128];			/* radius server				*/
	unsigned int radiusport;		/* radius port					*/
	unsigned int authtimeout;		/* authentication timeout			*/

	int verbose;
} GLOBAL;

GLOBAL global;					/* global variables 				*/

#define LEGAL_SIZE(x) sizeof((x))-1		/* calculate useable string space		*/

void fnInitialize();
void fnGatherInformation();
void fnPrintInformation();
void fnPrintHelp(char *cmd);
void fnGeneratePacket(RADIUS_HEADER *radhead);
int fnGeneratePasswordHash(RADIUS_HEADER *radhead);
void fnGenerateRequestAuthenticator(unsigned char *auth);
void fnCreateAttribute(RADIUS_HEADER *radhead, unsigned char attr_type, unsigned char attr_length, int data_type, void *attr_value);
void fnCalculateHeaderLength(RADIUS_HEADER *radhead);
void fnPrintHash(unsigned char *,int);
int fnSendAndReceivePacket(RADIUS_HEADER *radhead);

int main(int argc, char **argv)
{
	RADIUS_HEADER radhead;			/* radius header to be sent out			*/
	int c;
	int rc;
	
	fnInitialize(&radhead);			/* initialize the header and global variables	*/

	while ((c = getopt(argc, argv, "hvu:p:s:r:c:t:")) != EOF)
	{
		switch (c)
		{
			case 'v':		/* enable verbose output			*/
				global.verbose = 1;
				break;
			case 'u':		/* set username					*/
				strncpy(global.username,optarg,LEGAL_SIZE(global.username));
				break;
			case 'p':		/* set cleartext password			*/
				strncpy(global.password.pw_clear,optarg,LEGAL_SIZE(global.password.pw_clear));
				break;
			case 's':		/* set shared secret				*/
				strncpy(global.sharedsecret,optarg,LEGAL_SIZE(global.sharedsecret));
				break;
			case 'r':		/* set radius server				*/
				strncpy(global.radiusserver,optarg,LEGAL_SIZE(global.radiusserver));
				break;
			case 'c':		/* set server port				*/
				global.radiusport = atoi(optarg);

				if ((global.radiusport <= 0) || (global.radiusport >= 65535))
					global.radiusport = RADIUS_PORT;

				break;
			case 't':		/* set auth timeout value			*/
				global.authtimeout = atoi(optarg);

				if ((global.authtimeout <= 0) || (global.authtimeout >= 65535))
					global.authtimeout = AUTH_TIMEOUT;
				break;
			case 'h':		/* print help menu				*/
				fnPrintHelp(argv[0]);
		}
	}

	fnGatherInformation();			/* read user/pass/shared secret/server info from stdin 	*/

	if (global.verbose)			/* if verbose is on, print verification information	*/
		fnPrintInformation();

	fnGeneratePacket(&radhead);		/* generate our radius packet				*/

	rc = fnSendAndReceivePacket(&radhead);	/* send the radius packet to the server			*/

	return rc;
}

/*
 * fnInitialize
 *
 * This function is responsible for initializing the global structure as well
 * as clearing the radius header.
 *
 */

void fnInitialize(RADIUS_HEADER *radhead)
{
	memset(&global,0,sizeof(GLOBAL));
	memset(radhead,0,sizeof(radhead));

	radhead->rad_attr = NULL;

	global.radiusport = RADIUS_PORT;	/* set default port				*/
	global.authtimeout = AUTH_TIMEOUT;	/* set default auth timeout			*/

	srand(time(NULL));			/* seed random with current time		*/

	return;
}

/*
 * fnGatherInformation
 *
 * Read username/password/shared secret/server information from stdin.
 *
 */

void fnGatherInformation()
{
	if (!global.username[0])		/* if username isn't set, ask for it	*/
	{
		fprintf(stdout,"Enter Username: ");
		fflush(stdout);
		
		fgets(global.username,LEGAL_SIZE(global.username),stdin);
		global.username[strlen(global.username)-1] = 0;
	}

	if (!global.password.pw_clear[0])	/* if password isn't set, ask for it	*/
#ifdef SUNOS
		strncpy(global.password.pw_clear,getpassphrase("Enter Password: "),LEGAL_SIZE(global.password.pw_clear));
#else
		strncpy(global.password.pw_clear,getpass("Enter Password: "),LEGAL_SIZE(global.password.pw_clear));
#endif

	if (!global.sharedsecret[0])		/* if shared secret isn't set, ask for it 	*/
#ifdef SUNOS
		strncpy(global.sharedsecret,getpassphrase("Enter shared secret: "),LEGAL_SIZE(global.sharedsecret));
#else
		strncpy(global.sharedsecret,getpass("Enter shared secret: "),LEGAL_SIZE(global.sharedsecret));
#endif

	if (!global.radiusserver[0])		/* if radius server isn't set, ask for it	*/
	{
		fprintf(stdout,"Enter Radius Server: ");
		fflush(stdout);

		fgets(global.radiusserver,LEGAL_SIZE(global.radiusserver),stdin);
		global.radiusserver[strlen(global.radiusserver)-1] = 0;

		if (global.radiusserver[0] == 0)	/* if still not set, abort	*/
		{
			fprintf(stdout,"no radius server defined, aborting.\n");

			exit(1);
		}
	}
	
	fprintf(stdout,"\n");

	return;
}

/*
 * fnPrintInformation
 *
 * Print the information the person entered so that there's no question as to
 * whether or not there was a typo.
 *
 */

void fnPrintInformation()
{
	fprintf(stdout,"Using the following information\n-----------------\n");
	fprintf(stdout,"username: %s\n",global.username);
	fprintf(stdout,"password: %s\n",global.password.pw_clear);
	fprintf(stdout,"shared secret: %s\n",global.sharedsecret);
	fprintf(stdout,"server  : %s\n",global.radiusserver);

	return;
}

/*
 * fnPrintHelp
 *
 * Print the help menu.
 *
 */

void fnPrintHelp(char *cmd)
{
	fprintf(stdout,"radauth.c  1.00  01/13/00  mmiller@hick.org  Matt Miller\n");
	fprintf(stdout,"  Usage: # %s [OPTIONS]...\n\n",cmd);
	fprintf(stdout,"\tOPTIONS\n");
	fprintf(stdout,"\t-v\t\t\tverbose (output with verification)\n");
	fprintf(stdout,"\t-u [username]\t\tcleartext username\n");
	fprintf(stdout,"\t-p [password]\t\tcleartext password\n");
	fprintf(stdout,"\t-s [shared secret]\tshared secret for RADIUS server\n");
	fprintf(stdout,"\t-r [radius server]\tradius server to auth off of\n");
	fprintf(stdout,"\t-c [radius port]\tradius server port\n");
	fprintf(stdout,"\t-t [auth timeout]\tinterval to wait until auth timeout in seconds\n");
	fprintf(stdout,"\t-h\t\t\tthis menu\n");

	exit(0);
}

/*
 * fnGeneratePacket
 *
 * Generate the packet to be sent to the radius server
 *
 */

void fnGeneratePacket(RADIUS_HEADER *radhead)
{
	int hashpwlen = 0;

	radhead->rad_code = CODE_ACCESS_REQUEST;	/* set our radius code to Access-Request	*/
	radhead->rad_id	  = (getpid()%253) + 1;		/* set our rad id to the current process pid
							   modulas 253 + 1				*/

	fnGenerateRequestAuthenticator(radhead->rad_auth); /* Generate authenticator field		*/
	hashpwlen = fnGeneratePasswordHash(radhead);	/* Generate hashed password			*/

	/* Create the attributes, User-Name and User-Password 	*/
	fnCreateAttribute(radhead,ATTR_TYPE_USER_NAME,2 + strlen(global.username),DATATYPE_STRING,global.username);
	fnCreateAttribute(radhead,ATTR_TYPE_USER_PASSWORD,2 + hashpwlen,DATATYPE_STRING,global.password.pw_hash);

	/* Calculate the radius header length			*/
	fnCalculateHeaderLength(radhead);

#ifdef DEBUG	/* Print debug information if debugging		*/
	fprintf(stdout,"rad_code = %i\n",radhead->rad_code);
	fprintf(stdout,"rad_id   = %i\n",radhead->rad_id);
	fprintf(stdout,"hashpwlen= %i\n",hashpwlen);
	fnPrintHash(global.password.pw_hash,hashpwlen);
	fprintf(stdout,"rad_length = %i\n",ntohs(radhead->rad_length));
#endif
}

/*
 * fnGenerateRequestAuthenticator
 *
 * Generates a 16 octet string with pseudo-random numbers.
 * I had issues with actually using large random numbers, as radius seems to
 * not like packets that aren't full (or something).  I switched to something
 * sure for randomness and made every field a mininum of 127.
 *
 */

void fnGenerateRequestAuthenticator(unsigned char *auth)
{
	int x, randnumb;

	for (x = 0; x < REQ_AUTH_LENGTH;x++)	/* until then end of auth field has been reached 	*/
	{
		randnumb = rand()%128+127;
#ifdef DEBUG
		fprintf(stdout,"randnumb is = %i\n",randnumb);
#endif
		auth[x] = randnumb;
	}

	return;
}

/*
 * fnGeneratePasswordHash
 *
 * This generates the users password hashed with the shared secret.  A
 * more indepth description on how this is done can be found in RFC 2138
 *
 */

int fnGeneratePasswordHash(RADIUS_HEADER *radhead)
{
	unsigned char b[8][16], p[8][16], c[8][16];
	unsigned char ssra[49];
	int currlen = 0, pwlen = strlen(global.password.pw_clear), bpos = 0, ppos = 0, cpos = 0, x, sslen;

	/* clear our storage arrays */
	memset(b,0,128);	
	memset(p,0,128);
	memset(c,0,128);
	memset(ssra,0,49);

	sslen = strlen(global.sharedsecret);

	/* concatenate the shared secret and the radius authenticator field */
	snprintf(ssra,48,"%s%s",global.sharedsecret,radhead->rad_auth);

	/* do the follow atleast once */
	do
	{
		/* copy the, in 16 octet blocks, the users clear text password
		 * starting at position 0 in the clear text password array.
		 */
		strncpy(p[ppos],global.password.pw_clear+currlen,16);
	
		/* if the current length of the hashed password is not set,
		 * that means this is our first time through.  Therefore we
		 * calculate our first hash value (stored in b[0]) with the
		 * concatenated shared secret and radius authenticator.
		 */
		if (!currlen)
			md5_calc(b[0],ssra,sslen + REQ_AUTH_LENGTH);
		/* if this isn't our first time through, we must caculate our
		 * next hash value based off the shared secert concatentated
		 * XOR'd version of the clear text password and the original
		 * hash.
		 */
		else
		{
			snprintf(ssra,48,"%s%s",global.sharedsecret,c[cpos]);

			md5_calc(b[bpos],ssra,sslen + REQ_AUTH_LENGTH);

			cpos++;
		}

		/* from 0 to 16, XOR the clear text password with the hashed
		 * md5 output
		 */
		for (x = 0; x < 16; x++)
			c[cpos][x] = p[ppos][x] ^ b[bpos][x];

		/* increment out password position and temp position */
		bpos++; ppos++;

		currlen += 16;
	} while (currlen < pwlen); 

	x = 0;

	/* as long as the cipher block is valid, concatenate it onto our hash
	 * password
	 */
	while ((x <= 8) && (c[x][0]))
	{
		memcpy(global.password.pw_hash+(x*16),c[x],16);

		x++;
	}

	return currlen;
}

/*
 * fnCreateAttribute
 *
 * Responsible for adding an attribute which will be located in the attributes
 * field of the radius header.
 *
 */

void fnCreateAttribute(RADIUS_HEADER *radhead, unsigned char attr_type,unsigned char attr_length, int data_type, void *attr_value)
{
	RADIUS_ATTR *curr = radhead->rad_attr;	
	int *intval = (int *)attr_value;

	if (!curr)	/* if there aren't any attributes set, create the first one	*/
	{
		radhead->rad_attr = (RADIUS_ATTR *)malloc(sizeof(RADIUS_ATTR));
		curr = radhead->rad_attr;
	}
	else		/* otherwise find the last position and append to it		*/
	{
		while (curr->next)
			curr = curr->next;

		curr->next = (RADIUS_ATTR *)malloc(sizeof(RADIUS_ATTR));
		curr = curr->next;
	}

	if (!curr)		/* malloc failure.	*/
	{
		fprintf(stderr,"malloc failure, abort.\n");

		exit(1);
	}

	curr->next = NULL;

	curr->attr_type   = attr_type;		/* set the attribute type		*/
	curr->attr_length = attr_length;	/* set the attribute length		*/
	curr->datatype   = data_type;		/* set the attribute datatype.  this
						   value is NOT sent to the radius server*/

	switch (data_type)			/* copy based on our datatype		*/
	{
		case DATATYPE_STRING:
			strncpy(curr->attr_data.string,(char *)attr_value,LEGAL_SIZE(curr->attr_data.string)-1);
			break;
		case DATATYPE_ADDRESS: 
			curr->attr_data.address = *intval;
			break;
		case DATATYPE_INTEGER: 
			curr->attr_data.integer = *intval;	
			break;
		case DATATYPE_TIME:
			curr->attr_data.time = *intval;
			break;
	}

	return;
}

/*
 * fnCalculateHeaderLength
 *
 * Calculates the radius header length once everything is established.
 *
 */

void fnCalculateHeaderLength(RADIUS_HEADER *radhead)
{
	int headlength = 20;	/* smallest header is 20 bytes	code(1) + id(1) + length(2) + auth(16) */
	RADIUS_ATTR *curr = radhead->rad_attr;

	while (curr)		/* until we reach the end of our attributes, keep adding		*/	
	{
		headlength += curr->attr_length;

#ifdef DEBUG
		fprintf(stdout,"attr length = %i\n",curr->attr_length);
#endif

		curr = curr->next;
	}

	radhead->rad_length = htons(headlength);	/* set the final length					*/

	return;
}

/*
 * fnPrintHash
 *
 * Prints the hexidecimal version of the md5 hash'd password.  This is a debug
 * function only.
 *
 */

#ifdef DEBUG
void fnPrintHash(unsigned char *hash, int len)
{
	int x = 0;

	fprintf(stdout,"hash: ");

	for (;x < len;x++)
		fprintf(stdout,"%02x",hash[x]);

	fprintf(stdout,"\n");

	return;
}
#endif

/*
 * fnSendAndReceivePacket
 *
 * Send our radius header to the server and wait for a reply
 * Returns 0 if granted access, 2 if denied, or 1 if something else happened (like no response).
 *
 */

int fnSendAndReceivePacket(RADIUS_HEADER *radhead)
{
	RADIUS_ATTR *curr = radhead->rad_attr;
	unsigned char packet[ntohs(radhead->rad_length)];
	RADIUS_HEADER response;
	int pktpos = 0, sock, slen;
	struct sockaddr_in s;
	struct hostent *h;
	struct timeval tv;
	fd_set fdread;

	/* clear the packet to be sent */
	memset(packet,0,htons(radhead->rad_length));

	/* copy the first 20 bytes of the radius header.  this size is static
	 * per RFC.
	 */
	memcpy(packet,(char *)radhead,20);		

	/* set the current position in the packet to 20 */
	pktpos = 20;

	/* until we reach the end of our attributes, do the following	*/
	while (curr)	
	{
		/* copy the first 2 bytes of the attribute field (type
		 * and length) 
		 */
		memcpy(packet+pktpos,curr,2);	

		/* increment the packet position by 2 */
		pktpos += 2;

		/* copy to the packet and increment depending on our datatype
		 */
		switch (curr->datatype)
		{
			case DATATYPE_STRING:
				memcpy(packet+pktpos,curr->attr_data.string,curr->attr_length-2);
				pktpos += curr->attr_length-2;
				break;
			case DATATYPE_ADDRESS:
				memcpy(packet+pktpos,&curr->attr_data.address,curr->attr_length-2);
				pktpos += curr->attr_length-2;
				break;
			case DATATYPE_INTEGER:
				memcpy(packet+pktpos,&curr->attr_data.integer,curr->attr_length-2);
				pktpos += curr->attr_length-2;
				break;
			case DATATYPE_TIME:
				memcpy(packet+pktpos,&curr->attr_data.time,curr->attr_length-2);
				pktpos += curr->attr_length-2;
				break;
		}

		curr = curr->next;
	}

	/* create UDP socket */
	if ((sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) <= 0)
	{
		fprintf(stdout,"unable to allocate udp socket, abort.\n");

		exit(1);
	}

	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(global.radiusserver);
	s.sin_port = htons(global.radiusport);

	if (s.sin_addr.s_addr == -1)
	{
		if (!(h = gethostbyname(global.radiusserver)))
		{
			fprintf(stdout,"unable to resolve radius server: %s. abort.\n",global.radiusserver);

			exit(1);
		}

		memcpy(&s.sin_addr.s_addr,h->h_addr,h->h_length);
	}

	/* send the packet to the radius server */

	if (sendto(sock,(char *)packet,htons(radhead->rad_length),0,(struct sockaddr *)&s,sizeof(s)) < 0)
	{
		fprintf(stdout,"error sending UDP packet to radius server. abort.\n");

		exit(1);
	}

	fprintf(stdout,"Authentication request sent to %s:%i ... (timeout = %i)\n",global.radiusserver,global.radiusport,global.authtimeout);

	while (1) {
		int ret;
		slen = sizeof(s);

		FD_ZERO(&fdread);
		FD_SET(sock,&fdread);

		tv.tv_sec = global.authtimeout;
		tv.tv_usec = 0;

		/* if nothing is received in 30 seconds, authentication has failed. */
		if (!select(sock + 1, &fdread, NULL, NULL, &tv))
		{
			fprintf(stdout,"failed to receive a reply from the server, authentication FAILED.\n");

			return 1;
		}

		/* otherwise receive the packet and calculate the ret code */
		if (recvfrom(sock,&response,sizeof(response),0,(struct sockaddr *)&s,&slen) < 20) {
			fprintf(stdout,"Got invalid response: ret=%d, ignoring\n", ret);
			continue;
		}

		/* If the id doesn't match, ignore this response */
		if (response.rad_id != packet[1]) {
			fprintf(stdout,"Ignoring response with wrong id: %d != %d\n", response.rad_id, packet[1]);
			continue;
		}

		switch (response.rad_code)
		{
			case 2:		/* Access-Accept	*/
				fprintf(stdout,"Access GRANTED. (code = 2)\n");
				return 0;
			case 3:		/* Access-Reject	*/
				fprintf(stdout,"Access DENIED. (code = 3)\n");
				return 2;
			case 11:
				fprintf(stdout,"challenge issued, ignored. (code = 11)\n");
				return 1;
			default:
				fprintf(stdout,"unknown code.  (code = %i)\n",response.rad_code);
				return 1;
		}
	}
}
