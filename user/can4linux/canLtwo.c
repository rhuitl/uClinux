#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include <can4linux.h>



int can_open(int port)
{
char dev[100];
    sprintf(dev,"/dev/can%d", port);
    return open(dev, O_RDWR);
}

int can_close(int fd)
{
    return close(fd);
}

int can_send(int fd, int len, char *message)
{
char     *token;
canmsg_t tx;
int      j, sent=0;
 
    if(( token = strtok(message, ":") ) != NULL ) {
        tx.flags = 0;
        if( token[0] == 'r' || token[0] == 'R' ) {
            tx.flags = MSG_RTR;
            tx.id = strtol(&token[1], NULL,0);
            tx.length = len;
        } else {
            tx.id = strtol(token, NULL, 0);
            j = 0;
            while( (token = strtok(NULL, ",")) != NULL ) {
                tx.data[j++] = strtol(token, NULL, 0);
            }
            tx.length = (len > 0 ? len : j);
        }
        sent = write(fd, &tx, 1);
        return 1;
    } else {
       return -1;
    }
}


#if 0
int can_filter(int fd,char *fstring) {
  char *token;
  int i;
  if(( token = strtok(fstring,",")) != NULL ) {
    if( token[0] == '*' ) {
      can_Config(fd, CONF_FILTER, 0 ); 
 printf("\nfilter disabled");
    } else {
      can_Config(fd, CONF_FILTER, 1 );
      can_Config(fd, CONF_FENABLE, strtol(token,NULL,0));
printf("\naccept %d",strtol(token,NULL,0));
    }
    while((token=strtok(NULL,",")) != NULL ) {
      can_Config(fd, CONF_FENABLE, strtol(token,NULL,0));
printf("\naccept %d",strtol(token,NULL,0));
    }
    return 1;
  }
  return -1;
}  
#endif


/**
* simply read and format a CAN message
* 'messanger' like formatting
*/
char *can_read1(int fd, int timeout)
{
fd_set   rfds;
struct   timeval tv;
int      got,i,j;
canmsg_t rx[80];
static char databuf[4096];
char     *s;
char     type;

  FD_ZERO(&rfds);
  FD_SET(fd,&rfds);

  /* wait some time  before process terminates, if timeout > 0 */
  tv.tv_sec  = 0;
  tv.tv_usec = timeout;
  s          = &databuf[0];
  got        = 0;
  if( select(FD_SETSIZE, &rfds, NULL, NULL, ( timeout > 0 ? &tv : NULL )) > 0 && FD_ISSET(fd,&rfds) ) {

      got = read(fd, rx , 79);
      if( got > 0) {
	for(i = 0; i < got; i++) {
	  /* why ???, you are overwriting something if length = 8 */
	  /* rx[i].data[rx[i].length] = 0; */
	  if(rx[i].flags & MSG_BOVR) {
	    type = 'O';
	  } else if(rx[i].flags & MSG_EXT) {
	    type = 'e';
	  } else {
	    type = '.';
	  }
	  if( rx[i].flags & MSG_RTR ) {
	    s += sprintf(s, "%12lu.%06lu 0x%08lx R %c",
		    rx[i].timestamp.tv_sec,
		    rx[i].timestamp.tv_usec,
		    rx[i].id, type) ;
          }
	  else {
	    s += sprintf(s, "%12lu.%06lu 0x%08lx . %c %d ",
		    rx[i].timestamp.tv_sec,
		    rx[i].timestamp.tv_usec,
		    rx[i].id, type, rx[i].length );      
	    for(j = 0; j < rx[i].length; j++) {
	      s += sprintf(s, " 0x%02x", rx[i].data[j]); 
	    }
#ifdef ASCII_AT_THE_END
	    for( ; j < 8; j++) {
	      s += sprintf(s, "  .  "); 
	    }
	    s += sprintf(s, " '%s'", rx[i].data);
#endif
          }
          /* don't end the output with NL */
	  if(i + 1 < got) s += sprintf(s, "\n");
	} 
      }
  }
return databuf;
}

/**
* formattet read like the "horch" does.
* Formatting can controlled by some format options
* switch time stamp on/off
* display data in hex, dec, or ascii
*
* 100/0x064 : sD : 55 02 03 04 05 06 07 aa
* 1011800542.524542   100/0x064 : sD : 55 02 03 04 05 06 07 aa
* 100/0x064 : sD : 085 002 003 004 005 006 007 170
*/
char *can_read2(int fd, int timeout)
{
fd_set   rfds;
struct   timeval tv;
int      got,i,j;
canmsg_t rx[80];
static char databuf[4096];
char     *s;
unsigned char     type;
unsigned char     rtr;

    FD_ZERO(&rfds);
    FD_SET(fd,&rfds);

    /* wait some time  before process terminates, if timeout > 0 */
    tv.tv_sec  = 0;
    tv.tv_usec = timeout;
    s          = &databuf[0];
    got        = 0;
    if( select(FD_SETSIZE, &rfds, NULL, NULL, ( timeout > 0 ? &tv : NULL )) > 0 && FD_ISSET(fd,&rfds) ) {

	got = read(fd, rx , 79);
	if( got > 0) {
	  for(i = 0; i < got; i++) {
	    /* why ???, you are overwriting something if length = 8 */
	    /* rx[i].data[rx[i].length] = 0; */
	    if(rx[i].flags & MSG_BOVR) {
	      type = 'O';
	    } else if(rx[i].flags & MSG_EXT) {
	      type = 'e';
	    } else {
	      type = 's';
	    }
	    if(rx[i].flags & MSG_RTR) {
	      rtr = 'R';
	    } else {
	      rtr = 'D';
	    }

	    s += sprintf(s, "%12lu.%06lu 0x%08lx : %c%c(%d) : ",
		    rx[i].timestamp.tv_sec,
		    rx[i].timestamp.tv_usec,
		    rx[i].id, type, rtr, rx[i].length );      
	    if(rtr == 'D') {
		for(j = 0; j < rx[i].length; j++) {
		    s += sprintf(s, " 0x%02x", rx[i].data[j]); 
		}
	    }
#ifdef ASCII_AT_THE_END
	    for( ; j < 8; j++) {
	      s += sprintf(s, "  .  "); 
	    }
	    s += sprintf(s, " '%s'", rx[i].data);
#endif
            }
            /* don't end the output with NL */
	    if(i + 1 < got) s += sprintf(s, "\n");
        }
    }
    return databuf;
}


/**
* can_read - read only one message
*
* should be used on a file descriptor with data available
*
* formattet read like the "horch" does.
* Formatting can controlled by some format options
* switch time stamp on/off
* display data in hex, dec, or ascii (not implemented yet)
*
* 100/0x064 : sD : 55 02 03 04 05 06 07 aa
* 1011800542.524542   100/0x064 : sD : 55 02 03 04 05 06 07 aa
* 100/0x064 : sD : 085 002 003 004 005 006 007 170
*/
char *can_read(int fd)
{
canmsg_t rx[80];
static char databuf[4096];
char     *s;
unsigned char     type;
unsigned char     rtr;
int i, j, got;


	/* retrieve only one message */ 
	got = read(fd, rx , 1);
	if( got == 1) {
	    /* why ???, you are overwriting something if length = 8 */
	    /* rx[i].data[rx[i].length] = 0; */
	    if(rx[i].flags & MSG_BOVR) {
	      type = 'O';
	    } else if(rx[i].flags & MSG_EXT) {
	      type = 'e';
	    } else {
	      type = 's';
	    }
	    if(rx[i].flags & MSG_RTR) {
	      rtr = 'R';
	    } else {
	      rtr = 'D';
	    }

	    s += sprintf(s, "%12lu.%06lu 0x%08lx : %c%c(%d) : ",
		    rx[i].timestamp.tv_sec,
		    rx[i].timestamp.tv_usec,
		    rx[i].id, type, rtr, rx[i].length );      
	    if(rtr == 'D') {
		for(j = 0; j < rx[i].length; j++) {
		    s += sprintf(s, " 0x%02x", rx[i].data[j]); 
		}
	    }
#ifdef ASCII_AT_THE_END
	    for( ; j < 8; j++) {
	      s += sprintf(s, "  .  "); 
	    }
	    s += sprintf(s, " '%s'", rx[i].data);
#endif
            }
            /* don't end the output with NL */
	    if(i + 1 < got) s += sprintf(s, "\n");
    return databuf;
}
