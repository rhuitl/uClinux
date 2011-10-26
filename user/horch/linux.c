/* linux - device specific part of Horch
*/



#include <horch.h>

#include <sys/types.h>
#include <sys/socket.h>

#define MAXLINE		1024
#define MSG_TIMEOUT	100

static void clean(void);

static struct timeval	tv, tv_start;
static struct timezone	tz;


static int can_fd;
/* static int server_fd = 1; */

struct sockaddr_in fsin;		/* UDP socket */

/*
 * =========================================================
 * LINUX system specific part
 * =========================================================
 */

/**************************************************************************
*
* server_send
*
* changes the \n line end to \r\n
*/
int server_send(char *line)
{
int len;
    
    len = strlen(line);
    line[len -1] = '\r';
    line[len ]   = '\n';
    return(send(server_fd, (void *)line, len + 1, 0));
}

int set_up(void)
{
int ret;
char line[40];

    atexit(clean);

#ifndef SIM
    if(( can_fd = open(device,
			/* O_RDONLY */
			O_RDWR
    				)) < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
	exit(1);
    }
    if(o_bitrate != 0) {
	sprintf(line, " %d\n", o_bitrate);
	set_bitrate(line);
    }

#endif

    BDEBUG("message structure canmsg_t has %d bytes\n", sizeof(canmsg_t));


    if(!o_server) {
	/* set terminal mode */
	ret = system("stty cbreak -echo");
	if(ret != 0) {
	    fprintf(stderr, "  system(stty) returns %d\n", ret);
	}
    }
    /* pe-set time structures */
    gettimeofday(&tv_start, &tz);
    return 0;
}

void clean_up(void)
{
#ifndef SIM
    close(can_fd);
#endif
    clean();
    exit(0);
}

int    udp_event_loop() {}

int server_event_loop(void)
{
/*----------------------------------------------------------------*/
SOCKET listenfd;                /* incoming connection socket fd  */
/* SOCKET asd; */
extern SOCKET server_fd;

int established = 0;

struct sockaddr_in servaddr;    /* incoming connection address */
struct sockaddr_in cliaddr;     /* incoming connection address */
int clilen;			/* size of client socket struct */

int maxfd;                      /* maximum fd (optimization for select) */
int maxi;                       /* number of clients ??? */
int i, j;                       /* looping index */
int rcnt;			/* receive cnt, number of received bytes */
char in_line[MAXLINE];		/* command input line from socket to horch */

    /*
     * Open a TCP socket (an Internet stream socket).
     * 
     */

    BDEBUG("Open socket\n");

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0) {
	fprintf(stderr, "Socket open failed: %d\n", errno);
	goto TCP_SERVER_DONE;
    }
    BDEBUG("Got socket fd %d\n", listenfd);

    /*
    * Bind our local address so that the client can send to us.
    */
    memset((void *)&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family         = AF_INET;
    /* servaddr.sin_addr.s_addr = htonl(INADDR_ANY); */
    servaddr.sin_port           = htons(o_portnumber);

    if (bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
	fprintf(stderr, "TCPserver: Socket bind failed: %d\n", errno);
	goto TCP_SERVER_DONE;
    }

    BDEBUG("\r\nHorch TCPserver, listening on port %d\r\n", o_portnumber);
    /*
    * loop forever (daemons never die!)
    */
    for ( ; ; ) {
	/*
	* Set socket to passive mode
	* and ask kernel to buffer upto LISTENQ (inet.h)
	*/
	/********************************************************************/
	/* API-Call listen for connections */
	/********************************************************************/
	BDEBUG("TCPserver: Listening for connection\n");

	if(listen(listenfd, 1) < 0) {
	    printf("TCPserver: Socket listen failed: %d\n", errno);
	}

	printf("\nWaiting for connections on port %d\n", o_portnumber);
	fflush(stdout);

	/*
	* Accept the client connection
	*/
        clilen = sizeof(cliaddr);
	server_fd = accept(listenfd, (struct sockaddr *) &cliaddr, 
		(socklen_t *)&clilen);
	if (server_fd < 0) {
	      printf("TCPserver: Socket accept failed: %d\n", errno);
	      goto TCP_SERVER_DONE;
	}
        /* save the new socketdescriptor */
        /* server_fd = outregs.x.ax; */
        established = 1;

	printf("New client: %s, port %u; Assigning fd#%d\n",
		    inet_ntoa(cliaddr.sin_addr), cliaddr.sin_port, server_fd);
	fflush(stdout);

        /* server_fd = asd; */	/* load static server_fd */ 


/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
{
canmsg_t rx[80];			/* receive buffer for read() */
canmsg_t *prx;			/* pointer to receive buffer */
fd_set rfds;
int got;				/* got this number of messages */
int i;
struct timeval tval;		/* use time out in W32 server */
static int select_flag = 0;	/* count erroneous select activity */ 


    while( read(can_fd, rx , 80 ) > 0); /* flush/remove old messages */
    reset_send_line();

    while(established)  {

	/* reinit everytime - see linux manual
	 * tval could be changed after select() call */
	tval.tv_sec = 0;		/* first try it with 1ms */
	tval.tv_usec = 1400;

        FD_ZERO(&rfds);
        FD_SET(can_fd, &rfds);		/* watch on fd for CAN */
#if 0
        FD_SET(0, &rfds);		/* watch on fd for stdin */
#endif
        FD_SET(server_fd, &rfds);	/* watch on fd for Client requests */

#if defined(TARGET_LINUX_PPC)
        /* select for:          read, write, except,  timeout */      
        if( select(FD_SETSIZE, &rfds, NULL, NULL,     &tval ) > 0 )
#else
        /* select for:          read, write, except, no-timeout */      
        if( select(FD_SETSIZE, &rfds, NULL, NULL,     NULL  ) > 0 )
#endif
        {
	    /* one of the read file descriptors has changed status */
	    /* fprintf(stderr, "."); fflush(stderr);         */

            if( FD_ISSET(can_fd, &rfds) ) {
            	/* it was the CAN fd */

/* got=read(can_fd, rx , 80 ); */
/* Stringpuffer für die TCPIP Ausgabe umfasst nur ca. 2000 Zeichen
 * 20 Zeilen x 70 Zeichen == 1400 Zeichen.
 * Nun sollte der Puffer nicht mehr überlaufen 
 */
 
/* got=read(can_fd, rx , 20 ); */
/* CAN-REport bekommt zerstückelte Zeilen und verkraftet dies nicht */

	    got=read(can_fd, rx , 20 );
	    if( got > 0) {
		/* Messages in read */
		if (debug) {
		    fprintf(stderr, "--------------\n");
		    fprintf(stderr, "Received got=%d\n", got);
		} 
		prx = &rx[0];
		/* for all received messages */
		for(i = 0; i < got; i++) {
		    if((rx[i].id < 0) || (filter(rx[i].id) == TRUE)) { 
			/* for all received messages */
			/* show_message(&rx[i]); */
/* prx muß auch bei False erhöht werden */
/* show_message() könnte zuviele Nachrichten nach 'send_line' schreiben */
			show_message(prx);
		    } 
		    prx++; /* nächste Nachricht */
		}


#if 0		
		if(send_line_cnt > 1500) 
#endif		
		{
		    /* formatted string reaches Buffer end !*/
		    j = display_line(send_line);
		    if (j == -1) {
		        if (debug) {
		            fprintf(stderr,"Error (display_line): %s\n",
		            		strerror(errno));
		        }    
		    }	
		    reset_send_line();
		    if(j == -1) {
			established = 0;
			break;
		    }
		}

	    } else {
	        /* read returned with error */
		fprintf(stderr, "- Received got = %d\n", got);
		fflush(stderr);
	    }
	    } /* it was the CAN fd */

            if( FD_ISSET(server_fd, &rfds) ) {
            	/* it was the stdio terminal fd */
            	/* Lines are coming here with \r\n */
            	rcnt = read(server_fd , in_line, MAXLINE);
		BDEBUG("%d new commands\n", rcnt);
		if(rcnt == -1) {
		    fprintf(stderr, "Error reading from socket %d\n", errno);
		    established = 0;
		} else {
/************************************************************************/
/* 
* select() kehrt für server_fd zurück, 
* obwohl der Client die Verbindung gelöst hat.
* rcnt ist immer 0 und die Schleife läuft endlos mit 100% CPU last.
*	select_flag soll diese Situation erkennen
*	Ursache unbekannt
*/
		    if (rcnt == 0) {
			select_flag++;  /* Test */
			if (select_flag > 50) {
			    established = 0;
			    fprintf(stderr, "Problem with TCP/IP connection\n");
			}
		    } else {
			select_flag = 0; /* Test */
		    }
/************************************************************************/

		    for(i = 0; i < rcnt; i++) {
			/* read input chars from recv buffer */
			if(change_format(in_line[i]) == -1) {
			    established = 0;
			}
		    }
		}
	    } /* Server-in/stdio fd */

	}
    }	/* while(established)  */
}
/*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
        fprintf(stderr, "Horch Server: close connection\n");
	if(close(server_fd) < 0) {
	    fprintf(stderr, "   socket close failed: %d\n", errno);
	}

    } /* for(; ; ;) */

   /************************************/
   /* Shutdown server, should not happen */
   /************************************/

TCP_SERVER_DONE:

    BDEBUG("TCPserver: Closing listening socket\n");
    /* if(socketClose(asd) < 0) { */
    if(close(server_fd) < 0) {
	 printf("TCPserver: Socket close failed %d\n", errno);
    }
    return 0;

}

void event_loop(void)
{
canmsg_t rx[80];			/* receive buffer for read() */
fd_set rfds;
int got;				/* got this number of messages */
int i;
struct timeval tval;		/* use time out in W32 server */


    /* On LINUX we need no time out for the select call.
     * we either, wiat for:
     * a message arrives on can_fd
     * a key was hit on stdin - fd=0
     */
    tval.tv_sec = 0;		/* first try it with 1ms */
    tval.tv_usec = 1400;

    while(1) {
        FD_ZERO(&rfds);
        FD_SET(can_fd, &rfds);		/* watch on fd for CAN */
        FD_SET(0, &rfds);		/* watch on fd for stdin */

#if defined(TARGET_LINUX_PPC)
        /* select for:          read, write, except,  timeout */      
        if( select(FD_SETSIZE, &rfds, NULL, NULL,     &tval ) > 0 )
#else
        /* select for:          read, write, except, no-timeout */      
        if( select(FD_SETSIZE, &rfds, NULL, NULL,     NULL  ) > 0 )
#endif
        {
	    /* one of the read file descriptors has changed status */
	    /* fprintf(stderr, "."); fflush(stderr);         */
        
            if( FD_ISSET(can_fd, &rfds) ) {
            	/* it was the CAN fd */

		got=read(can_fd, rx , 20 );
		if( got > 0) {
		    /* Messages in read */
		    if (debug) {
			fprintf(stderr, "--------------\n");
			fprintf(stderr, "Received got=%d\n", got);
		    } 
		    for(i = 0; i < got; i++) {
		        if((rx[i].id < 0) || (filter(rx[i].id) == TRUE)) { 
			    /* for all received messages */
			    show_message(&rx[i]);
			}
		    }
		} else {
		    /* read returnd with error */
		    fprintf(stderr,
		    	"- Received got=%d: id=%d len=%d msg='%s' \n",
			    got, rx[i].id, rx[i].length, rx[i].data );
		    fflush(stderr);
		}
	    } /* it was the CAN fd */

            if( FD_ISSET(0, &rfds) ) {
            	/* it was the stdio terminal fd */
            	i = read(0 , device, 40);
            	while(i--) {
		    change_format(device[i]);
		} /* while */
	    } /* stdio fd */
	} else {
	    if(o_show_status) {
	    char line[100];
		getStat(line); /* fills line !! */
		sprintf(line,"%s %.1f\n", line, f_busload);
		send_line_cnt = strlen(line);
		display_line(line);
		send_line_cnt = 0;
	    }
	}
    }
}


static void clean(void)
{
    if(o_server) {

    } else {
	system("stty sane");
    }
}

int show_system_time(char *line)
{
    gettimeofday(&tv, &tz);
    tv.tv_sec -= tv_start.tv_sec;
    /* tv.tv_usec /= 10000; */
    return(sprintf(line, "%12lu.%06lu  ", tv.tv_sec, tv.tv_usec));
    /* return(sprintf(line, "%3d.%02d  ", tv.tv_sec, tv.tv_usec)); */
}

/***********************************************************************
*
* write_message - write a can message with data from line
*
* .B Line
* contains information about a CAN message to be sent
* in ASCII format:
* .sp
* .CS
* [r] id 0{data}8
* .CE
* where r is a optional RTR Flag that has to be set.
* id is the CAN message identifier and data the optional zero to
* eight data bytes.
* the format of all numbers can be C-format decimal or hexa decimal number.
*
* RETURN:
*
*/



#define skip_space(p)  while(*(p) == ' ' || *(p) == '\t' ) (p)++
#define skip_word(p)  while(*(p) != ' ' && *(p) != '\t' ) (p)++

int write_message(
	int format,	/* if true - extended message format */ 
	char *line	/* write parameter line */
	)
{
unsigned char data[8] = {8, 7, 6, 5, 4, 3 , 2, 1};
unsigned char *lptr;
int len = 0;
/* unsigned char **endptr; */
unsigned char *endptr;
canmsg_t tx;			/* build transmit message */



    /* May be some check is needed if we have a valid and useful message */

    lptr = &line[0];
    skip_space(lptr);

    tx.flags = 0;
    if(format == 1) {
	tx.flags |= MSG_EXT;
    } else {
    }
    if(*lptr == 'r' || *lptr == 'R') {
	tx.flags |= MSG_RTR;
	skip_word(lptr);
    }
    skip_space(lptr);
    tx.id  = strtoul(lptr, &endptr, 0);
    tx.cob = 0;

    while( lptr != endptr) {
        lptr = endptr;
        tx.data[len] = (signed char)strtol(lptr, &endptr, 0);
	if(lptr != endptr) len++;
	if (len == 8 ) break; 
    }

    tx.length = len;

BDEBUG("Transmit %d, RTR=%s, len=%d\n", tx.id,
			((tx.flags == 0) ? "F" : "T"),
			tx.length);
			
    len = write(can_fd, &tx, 1);

    if (len < 0) {
    	/* Write Error */
printf("Write Error: %d\n", len);
    }
    
    if (len == 0) {
    	/* Transmit Timeout */
printf("Write Error: Transmit fehlgeschlagen\n", len);
    }

    return 0;
}	

/***********************************************************************
*
* set_acceptance - sets the CAN registers
*
* .B Line
* contains information about the content of the CAN
* registers "acceptance" and "mask"
* in ASCII format:
* .sp
* .CS
* 0x0707 0x00000000
* 1799
* .CE
* the format can be C-format decimal or hexa decimal number.
*
* Changing these registers is only possible in Reset mode.
*
* RETURN:
*
*/

int	set_acceptance(
	char *line
	)
{
unsigned char *lptr;
unsigned char *endptr;			/* unsigned char **endptr; */
unsigned int acm = 0xffffffff;
unsigned int acc = 0xffffffff;
Config_par_t  cfg;
volatile Command_par_t cmd;

    lptr = &line[0];

    skip_space(lptr);
    acc  = strtoul(lptr, &endptr, 0);

    lptr = endptr;
    skip_space(lptr);
    acm  = strtoul(lptr, &endptr, 0);

    cmd.cmd = CMD_STOP;
    ioctl(can_fd, COMMAND, &cmd);
    /* high acceptance, low mask for 11 bit ID */
    cfg.target = CONF_ACC; 
    cfg.val1    = acm;
    cfg.val2    = acc;
    /* fprintf(stderr,"ACM=%04x\n", acm); */
    ioctl(can_fd, CONFIG, &cfg);

    cmd.cmd = CMD_START;
    ioctl(can_fd, COMMAND, &cmd);
}

/***********************************************************************
*
* set_bitrate - sets the CAN bitrate
*
* .B Line
* contains information about the new bit rate
* in ASCII format:
* .sp
* .CS
* 125
* 500
* 0x31c
* .CE
* the format can be C-format decimal or hexa decimal number.
*
* Changing these registers is only possible in Reset mode.
*
* RETURN:
*
*/

int	set_bitrate(
	char *line
	)
{
extern int o_bitrate;
unsigned char *lptr;
unsigned char *endptr;			/* unsigned char **endptr; */
Config_par_t  cfg;
volatile Command_par_t cmd;

    /* default */
    o_bitrate = 125;
    
    lptr = &line[0];
    skip_space(lptr);

    o_bitrate  = strtoul(lptr, &endptr, 0);


    cmd.cmd = CMD_STOP;
    ioctl(can_fd, COMMAND, &cmd);
    /* high acceptance, low mask for 11 bit ID */
    cfg.target = CONF_TIMING; 
    cfg.val1    = o_bitrate;
    /* fprintf(stderr,"ACM=%04x\n", acm); */
    ioctl(can_fd, CONFIG, &cfg);

    cmd.cmd = CMD_START;
    ioctl(can_fd, COMMAND, &cmd);
}

/* fill line with status info */
void getStat(char *line)
{
CanStatusPar_t status;
    ioctl(can_fd, STATUS, &status);
    sprintf(line, ":: sja1000 %d %d %d %d %d %d",
    	status.baud,
    	status.status,
    	status.error_warning_limit,
    	status.rx_errors,
    	status.tx_errors,
    	status.error_code
    	);
}

