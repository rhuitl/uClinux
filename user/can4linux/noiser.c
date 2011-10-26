
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <can4linux.h>

#define STDDEV "can1"

#define MESSG_BLOCK 10 
#define USE_RTR 1

int main(int argc,char **argv)
{
int fd;
int i,sent;
canmsg_t tx[100];
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

    while(1){
      /* fill message block with data */
      for(i = 0; i < MESSG_BLOCK; i++) {
        tx[i].flags = 0;
	tx[i].id    = 1 + (int)( 500.0*rand()/RAND_MAX+1.0 );
	sprintf( tx[i].data, "%ldabcde", tx[i].id);
	printf("send: '%s' \n", tx[i].data);
	tx[i].length = strlen(tx[i].data); 

#if USE_RTR 
        if(   tx[i].id == 500
           || tx[i].id == 450
           || tx[i].id == 400
           || tx[i].id == 350
           || tx[i].id == 300
           || tx[i].id == 250
           || tx[i].id == 200
           || tx[i].id == 150 
           || tx[i].id == 100 
           || tx[i].id ==  50 )
	  tx[i].flags |= MSG_RTR;
#endif

      }
      sent=write(fd, tx, MESSG_BLOCK );
      sleep(1); 
      if(sent <= 0) {
	printf("not ready"); break;
      }
    }
    close(fd);
    return 0;
}
















