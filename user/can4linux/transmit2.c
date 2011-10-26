
/*   Transmit sends a bunch of telegrams by filling them with       */
/*   different CANids and data bytes. You may send more than one    */
/*   telegram with write just by sending out an array of telegrams. */
/*   After writing, the programm is looking if something was      . */
/*   received. */
 
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <can4linux.h>

#define STDDEV "can1"

int main(int argc,char **argv)
{
int fd;
int i,sent;
canmsg_t tx[256];
canmsg_t rx;
char device[40];

    if(argc == 2) {
	sprintf(device, "/dev/%s", argv[1]);
    }
    else {
	sprintf(device, "/dev/%s", STDDEV);
    }
    printf("using CAN device %s\n", device);
    
    if(( fd = open(device, O_RDWR )) < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
        exit(1);
    }

    for(i=0;i<16;i++) {
      sprintf( tx[i].data,"msg%d",i);
      printf("sending '%s'\n",tx[i].data );
      tx[i].flags = 0;  
      tx[i].length = strlen(tx[i].data);  
      tx[i].id=500 + i;

    }

    while(1) {
    int got;
    int error;
	printf("fast xmit message\n");
	sent=write(fd, tx, 16 ); sleep(1);
	if(sent <= 0) {
	    printf("not ready");
	}
	usleep(500000);
	do {
	    got = read(fd, &rx, 1);
	    if( got > 0) {
		if(rx.flags & MSG_ERR_MASK) {
		    error = 1;
		} else {
		    error = 0;
		}
	        printf("RX %s id=%ld len=%d flags=0x%x \n",
			error ? "ERROR" : "" ,rx.id, rx.length, rx.flags);

	    } else {
	        printf("-> got nothing\n");
	    }
	    fflush(stdout);
	} while (got > 0);
	usleep(500000);
    }
    close(fd);
    return 0;
}

