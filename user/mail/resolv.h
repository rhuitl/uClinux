#include <netdb.h>
#include <netinet/in.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>

#define DEBUG 1
#define NS_PORT 53

/*Structures*/
struct nserver {
	short id;		 /* id number 16bit */
	short opcodes;  /* QR-1 OPCODE-4 AA-1 TC-1 RD-1 RA-1 Reserved-3 Rcode-4 */ 
	short qdcount;  /* Question Count 16bit */
	short ancount;  /* Answer Count 16bit */
	short nscount;  /* Authority Count 16bit */
	short arcount;  /* Resource Count 16 Bit */
	char  data[255]; /*Fields - may have to extend?!?*/
};

/* The reasson for the ttl high and low is if there was just a long then it
would occour on an odd address boundry and be shifted - but we dont really care
about ttl anyway */
struct nsreply { 	
	unsigned short name; 	/* Offset - ie c00c = 1100 0000 0000 1100 - which is 12 bytes offset*/
	unsigned short type;   	/*has a type of 1 = A f = 15 = MX (rfc 974 && 973)*/
	unsigned short aclass; 	/* has type 0 ??? */
	//unsigned long ttl; 	/* time to live high */
	unsigned short ttlhigh; 	/* time to live high */
	unsigned short ttllow; 		/* time to live low  */
	unsigned short datalength;/* length of data in bytes*/
	unsigned char  data[64];	/* actual data*/
};

/*function prototypes*/
int resolv (struct in_addr* ina,char* ipstr);

/*private prototypes*/
int clientSocket(short send_to_port,char* str_nsaddr);
int addOption(unsigned char **optionptr,  char *data, char datalength);
int getrand(int max);
int parseip (unsigned char** strptr, char* ipstr);
int getData(short type,struct nserver *nsrec,char *data);

int recievePacket (struct nserver* nsrec,short id,int client_socket);
int sendAndRecieve (char type,char *nameserver,char *ipstr,struct nserver *nsrec);
int sendPacket(char type,char * question,short *id,int client_socket);
int revparseip (struct nserver *ns,char *ipstr,char *outip);

