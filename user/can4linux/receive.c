#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>

#include <can4linux.h>

#define STDDEV "can0"

#define TotalMessages 6

int     set_bitrate(
        int fd,                 /* device descriptor */
        int baud                /* bit rate */
        )
{
Config_par_t  cfg;
volatile Command_par_t cmd;


    cmd.cmd = CMD_STOP;
    ioctl(fd, COMMAND, &cmd);

    cfg.target = CONF_TIMING;
    cfg.val1   = baud;
    ioctl(fd, CONFIG, &cfg);

    cmd.cmd = CMD_START;
    ioctl(fd, COMMAND, &cmd);
    return 0;
}

int set_mask( int fd, int mask )
{

int ret;
Config_par_t  cfg;

    cfg.target = CONF_ACCM;
    cfg.val1   = mask; /* mask */
    cfg.val2   = mask; /* mask */

    ret = ioctl(fd, CONFIG, &cfg);

    return ret;
}



int main(int argc,char **argv)
{
    int fd;
    int got;
    int i;
    int test=0;
    canmsg_t rx;
    char device[40];
    int baud = 125; /* default 125kbp*/
    int c;
    int M[TotalMessages];
    int counter = 0;

    sprintf(device, "/dev/%s", STDDEV);

    while ((c = getopt(argc, argv, "b:D:t")) != EOF) {
       switch (c) {
            case 'b': baud = atoi(optarg); 
            break;
	    case 'D': sprintf(device, "/dev/%s", optarg);
            break;
            case 't': test=1; 
            break;
            default: break;
       }
    }
    printf("using CAN device %s with bit rate %d k\n", device, baud);
    
    if(( fd = open(device, O_RDWR )) < 0 ) {
	fprintf(stderr,"Error opening CAN device %s\n", device);
        exit(1);
    }
    set_bitrate(fd, baud);

    printf("waiting for msg at 0x%p:\n", &rx);

    set_mask(fd, 0x0);

    for(i = 0; i < TotalMessages; i++)
        M[i] = 0;
    i = 0;
    while(1) {
      got=read(fd, &rx, 1);
      if( got > 0) {
        if(test){
              i %= TotalMessages;
              if(M[i]){
                  if(M[i] != rx.data[0]) {
                      printf("missed 0x%02X\n", M[i]);
          	      printf("loops:%d\n", counter);
                      exit(-1);
                  }
              } else {
                 M[i] = rx.data[0];
              } 
              i++;

        } else {
           printf("Received with ret=%d: %12lu.%06lu id=%ld len=%d flags=0x%x msg=[0x",
		    got, 
		    rx.timestamp.tv_sec,
		    rx.timestamp.tv_usec,
		    rx.id, rx.length, rx.flags );
	    for(i=0; i < rx.length; i++)
               printf("%02X", rx.data[i]);
	    printf("]\n");
	    fflush(stdout);
          }
      counter++;
      if((counter % 1000) == 0)
          printf("loops:%d\n", counter);
      }
#if 0
       else {
	printf("Received with ret=%d\n", got);
	fflush(stdout);
      }
	sleep(1);
#endif
    }

    close(fd);
    return 0;
}
