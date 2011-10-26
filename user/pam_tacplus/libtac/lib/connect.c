/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 * connect.c  Open connection to server.
 */

#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <stdlib.h>
#include <signal.h>

#include "tacplus.h"
#include "libtac.h"

/* Returns file descriptor of open connection
   to the first available server from list passed
   in server table.
*/
int tac_connect(u_long *server, int servers) {
	struct sockaddr_in serv_addr;
	struct servent *s;
	int fd;
	int tries = 0;

	if(!servers) {
		syslog(LOG_ERR, "%s: no TACACS+ servers defined", __FUNCTION__);
		return(-1);
	}

	while(tries < servers) {	

 		bzero( (char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = server[tries];

		s=getservbyname("tacacs", "tcp");
		if(s == NULL) 
			serv_addr.sin_port = htons(TAC_PLUS_PORT);
		else
			serv_addr.sin_port = s->s_port;

		if((fd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
       	   		syslog(LOG_WARNING, 
				"%s: socket creation error for %s: %m", __FUNCTION__,
							inet_ntoa(server[tries]));
			tries++;
			continue;
		}

		if(connect(fd, (struct sockaddr *) &serv_addr, 
						sizeof(serv_addr)) < 0)
    		{
     	  		syslog(LOG_WARNING, 
				"%s: connection to %s failed: %m", __FUNCTION__,
						inet_ntoa(server[tries]));
			tries++;
			continue;
    		}

		/* connected ok */
		TACDEBUG((LOG_DEBUG, "%s: connected to %s", __FUNCTION__, \
			       	inet_ntoa(server[tries])));

		return(fd);
	}

	/* all attempts failed */
	syslog(LOG_ERR, "%s: all possible TACACS+ servers failed", __FUNCTION__); 
	return(-1);

} /* tac_connect */


int tac_connect_single(u_long server) {
	return(tac_connect(&server, 1));
} /* tac_connect_single */
