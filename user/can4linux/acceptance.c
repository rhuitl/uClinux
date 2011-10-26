/* simple driver test: change the baudrate with ioctl()
* 
*
* first argument can be the device name -- else it uses can0
*
* if a second arg is given, it is used as new acceptance code
* if a third arg is given it is used as new acceptance mask 
* 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <can4linux.h>

#define STDDEV "can0"

/***********************************************************************
*
* set_accmask - sets the CAN acceptance and mask register
*
*
* Changing these registers only possible in Reset mode.
*
* RETURN:
*
*/

int	set_accmask(
	int fd,			/* device descriptor */
	int newcode,
	int newmask
	)
{
Config_par_t  cfg;
volatile Command_par_t cmd;


    cmd.cmd = CMD_STOP;
    ioctl(fd, COMMAND, &cmd);

    cfg.target = CONF_ACC; 
    cfg.val1   = newmask;
    cfg.val2   = newcode;
    ioctl(fd, CONFIG, &cfg);

    cmd.cmd = CMD_START;
    ioctl(fd, COMMAND, &cmd);
    return 0;
}


int	set_acccode(
	int fd,			/* device descriptor */
	int newcode
	)
{
Config_par_t  cfg;
volatile Command_par_t cmd;


    cmd.cmd = CMD_STOP;
    ioctl(fd, COMMAND, &cmd);

    cfg.target = CONF_ACCC;
    cfg.val1   = newcode;
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
int newmask = 0;
int newcode  = 0;

    printf("usage: %s [dev] [acc_code] [acc_mask]\n", argv[0]);
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
    	newcode = strtoul(argv[2], NULL, 0);
	printf("change acc_code to 0x%x\n", newcode);
	set_acccode(fd, newcode);
    }
    if(argc == 4) {
    	newcode = strtoul(argv[2], NULL, 0);
    	newmask = strtoul(argv[3], NULL, 0);
	printf("set acc_mask to 0x%x and acc_code to 0x%x\n",
				newcode, newmask);
	set_accmask(fd, newcode, newmask);
    }

    sleep(10);    
    close(fd);
    return 0;
}

