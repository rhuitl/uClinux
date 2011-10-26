/* simple driver test: change the bit rate registers with ioctl()
* 
*
* first argument can be the device name -- else it uses can0
*
* if a second arg is given, it is used as new bit rate
*
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <can4linux.h>

#define STDDEV "can0"

/***********************************************************************
*
* set_bitrate - sets the CAN bit rate
*
*
* Changing these registers only possible in Reset mode.
*
* RETURN:
*
*/

int	set_bitrate(
	int fd,			/* device descriptor */
	int baud		/* bit rate */
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



/*
*
*
*/
int main(int argc,char **argv)
{
int fd;
char device[40];
int newbaud = 250;

    printf("usage: %s [dev] [bit_rate]\n", argv[0]);
    if(argc > 1) {
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
    if(argc == 3) {
    	newbaud = atoi(argv[2]);
    }
    printf("set baudrate to %d Kbit/s\n", newbaud);
    set_bitrate(fd, newbaud);

    sleep(5);    
    close(fd);
    return 0;
}

