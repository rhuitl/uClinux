/* Resolv.c built using rfc 883 and additionally 974 and 973 */

#include "resolv.h"

#define NAMESERVER "139.130.4.5"
//#define NAMESERVER "203.24.151.1"

#define MAILA 0xfe
#define MAILB 0xfd
#define IP    0x01
#define ALL   0xff
#define MX    0x0f

#if 0
int main() {
	struct in_addr ina;
	resolv(&ina,"slashdot.org");
	printf("is %s\n",inet_ntoa(ina));
}
#endif

int resolv (struct in_addr* ina,char* ipstr) {
/* It tries to resolve the ip address by checking the name server if successful it
   modifies the in_addr structure with the last found address (multiple addresses 
	may be found)
	
	Args: ipstr - email address - "bob@kma.com"
	
	Retn: 0 Success 
			-1 Failure
 */
	
	struct nserver ns;
	char * tmpptr;
	char data[30];
	
	tmpptr = ipstr;
	
	memset(data,0x00,sizeof(data));
	
	/*remove leading name and '@' */
	while (1) {
		if (ipstr[0] == 0x00) {
			printf("'@'symbol not found in: %s\n",tmpptr);
			return -1;
		}
		if (ipstr[0] == '@') {
			ipstr++;
			break;
		}
		ipstr++;
	}
	printf("Lookup %s\n",ipstr);
	
	sendAndRecieve (ALL,NAMESERVER,ipstr,&ns);
	if (getData(MX,&ns,data) == -1) { /*Get the MX - mail exchange info*/
		/* if no good then try and find normal address and send it */
		printf("Couldnt find MX - try normal ip %s\n",ipstr);
		sendAndRecieve (IP,NAMESERVER,ipstr,&ns);
	}
	else {
		sleep(1);
		printf("Main Data - %s\n",((char*)data)+1);
		sendAndRecieve (IP,NAMESERVER,((char*)data)+1,&ns);
	}
	if (getData(IP,&ns,data) == 0) { /*Get the ip address of the Mail Exchange*/
		memcpy((char *)&ina->s_addr,data,4);
		printf("IP Found = %s\n",inet_ntoa(*ina));
		return 0;
	}
	return -1;
	
}

int getData(short type,struct nserver *nsrec,char *data) {
		
/* Desc: Rips the 1st found data of a particular type out of a 
			nsserver packet
	Args: Type  0x01 IP address - 4 bytes of data
					0x0f MX - name server - unknown amount - 
						hopefully null trminated
						 
*/
	unsigned char* strptr;
	int var,i;
	struct nsreply *nr2;

	strptr = nsrec->data;
	while (strptr[0] != 0x00) { /* while not at end of the domain name */
		strptr += (strptr[0] + 1); /* add the length shown */
		//printf("strptr[0]=%02x\n",strptr[0]);
	}
	strptr += 5; /* five ending bytes */
	//printf("strptr[0]=%02x\n",strptr[0]);
	
	if ((htons(nsrec->ancount) != 0) || (htons(nsrec->nscount) != 0)) {
		printf("nsrec->ancount %04x\n",htons(nsrec->ancount));
		printf("nsrec->nscount %04x\n",htons(nsrec->nscount));
		var = htons(nsrec->ancount) + htons(nsrec->nscount);
	}
	else {
		printf("Strange Error - No Results\n");
		printf("nsrec->ancount %04x\n",htons(nsrec->ancount));
		printf("nsrec->nscount %04x\n",htons(nsrec->nscount));
		return -1;
	}
	
	printf("var = %d\n",var);

	
	for(i=0;i<var;i++) {
		//memcpy(&nr,strptr,sizeof(nr)-sizeof(nr.data));  /*copy the address into the structure*/
		nr2 = (struct nsreply*)strptr;
		printf("name = %04x\n",htons(nr2->name));
		printf("type = %04x\n",htons(nr2->type));
		printf("class = %04x\n",htons(nr2->aclass));	
		printf("ttlh = %04x\n",htons(nr2->ttlhigh));
		printf("ttll = %04x\n",htons(nr2->ttllow));
		printf("datalen = %04x\n",htons(nr2->datalength));
		//nr.data[htons(nr->datalength)] = '\0';
		//ina->s_addr = nr.ip;

		strptr += sizeof(*nr2)-sizeof(nr2->data)+htons(nr2->datalength);
		printf("a-%d b-%d c-%d\n",sizeof(*nr2),sizeof(nr2->data),htons(nr2->datalength));
		if (htons(nr2->type) == type) {
			printf("Woohoo match!!!\n");
			i = var; /*break*/
		}
	}
	
	if (htons(nr2->type) != type) {
		printf("No match! : nr2->type != %04x\n",type);
		return -1;
	} 
	/* We have a matching type*/
	strptr = nr2->data;
	
	if (type == MX) {
		strptr += 2;
		//printf("Strptr = %s\n",strptr);
		printf("Mailserver Prioity = %02x%02x\n",nr2->data[0],nr2->data[1]);
		revparseip(nsrec,strptr,data);
		printf("data = %s\n",data);
	}
	else if (type == IP) {
		/* memcpy it to data */
		memcpy(data,strptr,4);
	}
	return 0;
	
	
}



int sendAndRecieve (char type,char *nameserver,char *ipstr,struct nserver *nsrec) {

	short id;
	int client_socket;
	/* set up the socket */
	client_socket = clientSocket(NS_PORT,nameserver);
	printf("Client Socket Set up\n");

	/*send packet looking for ipstr*/
	if (sendPacket(type,ipstr,&id,client_socket) == -1) {
		return -1;
	}
	/*recieve the packet - hopefully */
	if (recievePacket(nsrec,id,client_socket) == -1) {
		return -1;
	}
	close(client_socket);
	return 0;
}
	
	
	
	
		
int sendPacket(char type,char * question,short *id,int client_socket) {
/* Desc: Forms and sends a packet to the name server with the name in question 
   		Use the standard nameing notation eg "aaa.bbb.com"
	
	Args: nameserver (IN) - ip address of the nameserver "123.123.123.123"
			qusetion (IN) - address you are trying to look up
			id (OUT) - randomly generated id string - used in comparison with 
						  returned packets
						  
	Retn:  0 success
			-1 failure
	
*/
	struct nserver ns;
	unsigned char* strptr;
	int bytes = 0;
	char buf[sizeof(struct nserver)];
	
	
	memset(&ns,0x00,sizeof(struct nserver));
	//memset(&nr,0x00,sizeof(struct nserver));

	ns.id = getrand(9999); /* random id */
	//printf("nsid = 0x%04x\n",ns.id);
	ns.opcodes = htons(0x0100); /* QUERY */
	//ns.opcodes = htons(0x0000); /* QUERY */
	ns.qdcount = htons(0x0001); /* 1 question */
	ns.ancount = htons(0x0000);
	ns.nscount = htons(0x0000);
	ns.arcount = htons(0x0000);
	
	/* Fill the strptr with the data */
	strptr = ns.data;
	bytes = parseip(&strptr,question);
	bytes += 17; /* 12(struct) + parseip + 1(00) + 2(0001) + 2(0001) */
	strptr[0] = 0x00;//end of string
	strptr++;
	strptr[0] = 0x00; //reserved
	strptr[1] = type; //QTYPE
	
	strptr += 2;

	strptr[0] = 0x00; //reserved
	strptr[1] = 0x01; //QCLASS
	
	memcpy(buf,&ns,sizeof(buf));
	bytes = send(client_socket, buf, bytes, 0);
	
	if(bytes == -1) {
		syslog(LOG_ERR,"error writing to client_socket");
		return -1;
	}
	
	*id = ns.id;

	return 0;
}

int recievePacket (struct nserver* nsrec,short id,int client_socket) {	
/* Desc: Recieves a packet and places the data in the nsreply structure
	Args: *nsreply - pointer to a nserver struct
			id - the id of the sent packet used for comparison to get the 
				  intented reply
	Retn: -1 on failure
			 0 on success
*/

	int bytes = 0;
	char buf[sizeof(struct nserver)];

	
	while(1){
		/* FIXME: Situation where the server does not respond - 
		must make non blocking reads*/
		
#if DEBUG	
		printf("Searching...\n");
#endif	
		recv(client_socket,buf,sizeof(buf),0);
		printf("Finished.\n");
	
		if(bytes == -1) {
			syslog(LOG_ERR,"error writing to client_socket");
			return -1;
		}
		memcpy(nsrec,buf,sizeof(buf));
		printf("id = %04x\n",htons(nsrec->id));
		if ((nsrec->id) == id) {
			if ((htons(nsrec->opcodes) & 0x000f) != 0) {
#if DEBUG		
				printf("This IP has no DNS address!!\n");
#endif		
				return -1;
			}
			/*else*/
#if DEBUG	
			printf("found!\n");
#endif	
			break;
		}
	}
}
	

int clientSocket(short send_to_port,char* str_nsaddr) {

	int client_socket;
	struct sockaddr_in client;
	struct in_addr ina;
	
	inet_aton(str_nsaddr,&ina);
	
	client_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	if(client_socket == -1) {
		syslog(LOG_ERR, "client socket err");
#if DEBUG
		perror("client socket");
#endif
		return -1;
	}
	
	memset(&client,0x00, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_port = htons(send_to_port);
	client.sin_addr.s_addr = ina.s_addr;

	if(connect(client_socket, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1) {
		syslog(LOG_ERR, "client connect error");
#if DEBUG
		perror("client connect");
#endif
		return -1;
	}
	
	return client_socket;	
}


int revparseip (struct nserver *ns,char *ipstr,char *outip) {
/* converts letters and nums to letters and dots 
	eg 2mx7thegrid3net0 ==> .mx.thegrid.net0
	make sure ipstr has enuff space to hold pointer names
	
	Args: (IN) ipstr - The start of the ip string (may lead to pointer)
			(IN) ns - So it may evaluate any pointers it encounters
			(OUT) outip - the finished product. 
	Note: ipstr is not reused to avoid range errors
*/ 
	char tmp[30];
	char *tmpptr;
	int j,i = 0;
	short tmpsh;
	int lastcount;
	
	memset(tmp,0x00,sizeof(tmp));
	tmpptr = ipstr;
	
	printf("Reversep tmpptr = %x,%x,%x\n",tmpptr[0],tmpptr[2],tmpptr[3]);
	printf("Reversep ipptr = %x,%x,%x\n",ipstr[0],ipstr[2],ipstr[3]);
	
	//exit(1);
	while (tmpptr[0] != 0x00) {	/* traverse the string until end*/
		lastcount = tmpptr[0]; 		/* copy reference number for later use */
		tmp[i] = '.'; 					/* replace reference number with a dot */
		for (j=0;j<lastcount;j++) {/* cycle until next reference number */
			i++;
			tmpptr++;
			tmp[i] = tmpptr[0];		/*copy data to tmp string */
		}
		tmpptr++;
		i++;
		printf("Reversep tmpptr = %s\n",tmpptr);
		if ((tmpptr[0] & 0xc0) == 0xc0) { 	/* if pointer and not a reference number*/
			printf("Pointer Found!\n");
			memcpy((char *)&tmpsh,tmpptr,sizeof(tmpsh));/* convert pointer to a short */
			tmpsh = (htons(tmpsh) ^ 0xc000);	/* remove the pointer indicator */
			tmpptr = &((char *)ns)[tmpsh];	/* go to the pointer location */
		}
	printf("Str = %s\n",tmp);
	}
	printf("Str = %s\n",tmp);
	memcpy(outip,tmp,strlen(tmp));
}
	
int parseip (unsigned char** strptr, char* ipstr) {
/* converts the letters and dots to leters and counts.
eg mx.thegrid.net ==> 2mx7thegrid3net
*/

	int i = 0;
	int count = 0;
	
	while (1) { /*loop until end*/
		//printf("ips[%d]=%c\n",i,ipstr[i]);
		if (ipstr[i] == '.') {
			//printf("adding %s,%d\n",ipstr,i);
			addOption(strptr,ipstr,i);
			
			ipstr += (i + 1);
			i = -1;
		}
		if (ipstr[i] == '\0') {
			//printf("adding %s,%d\n",ipstr,i);
			addOption(strptr,ipstr,i);
			break;
		}
		i++;
		count++;
	}

	return (count+1);
	
} 

int addOption(unsigned char **optionptr,  char *data, char datalength) {
/* if datalength is 0 it will not prepend the datalength */
	
	unsigned char *tmpptr;
	tmpptr = *optionptr;
	
	if (datalength != 0) {
		tmpptr[0] = datalength;
	}
	tmpptr++;
	memcpy(tmpptr, data, datalength);
	tmpptr += datalength;
	*optionptr = tmpptr;
	return 0;	
}

int getrand(int max) {
	
	int j;
	struct timeval tv;
	
	
	if (gettimeofday(&tv,NULL) != 0) {
		printf("Error getting time\n");
	}
	srand(tv.tv_sec);
	j=	1+(int)((float)max*rand()/(23457+1.0));
	//printf("j = %d\n",j); 

	return j;

}
	
	
