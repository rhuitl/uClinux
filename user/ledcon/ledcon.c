#include <linux/ledman.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define KIT_MAX		9
#define L2R_MAX		8

void killHandler(void);

extern char *optarg;
extern int optind, opterr, optopt;


char *command;
char *time_str;
int time = 100;

int main (int argc, char *argv[]) {

	int i = 0;
	int sequence = 0;
	int kit[] = { 7, 7, 3, 6, 4, 5, 1, 11, 2, 17};
	int left2right[] = {2, 1, 4, 3, 7, 6, 5, 11, 17};
	int led = 0;
	char c;
	struct sigaction sa;
	
	switch (argc) {
		case 1 : case 2 :
usage:			fprintf(stderr, "Usage:\t%s -s <sequence number> [flash time]\n", argv[0]);
			fprintf(stderr, "\t\t -l <led number> [flash time]\n");
			exit (1);
			break;
		case 4:
			time = atoi(argv[3]) * 1000;
			fprintf(stdout, "time: %i, ",time);
		case 3 :
			while ((c = getopt (argc, argv, "s:l:")) != EOF)
				switch (c) {
				  case 's':
					  sequence = atoi(optarg);
			fprintf(stdout, "sequence #: %i - ",sequence);
					  break;
				  case 'l':
					  led = atoi(optarg);
			fprintf(stdout, "led %i\n",led);
					  break;
				default :
			  		goto usage;
				}
			break;
		default :
			  goto usage;
			  break;

	} 
        sa.sa_handler = (void *)killHandler;
        sa.sa_mask = 0; //dont block any signals while this one is working
        sa.sa_flags = SA_RESTART; //restart the signal
        sigaction(SIGINT, &sa, NULL);

	ledman_cmd(LEDMAN_CMD_KILLTIMER, 0);

	switch (sequence) {
		case 1 :
			fprintf(stdout, " KIT \n");
			while(1) {
				for (i = 0; i <= (KIT_MAX - 1); i+=2) {
					ledman_cmd(LEDMAN_CMD_ON, kit[i]);
					ledman_cmd(LEDMAN_CMD_ON, kit[i + 1]);
					usleep(time);
					ledman_cmd(LEDMAN_CMD_OFF, kit[i]);
					ledman_cmd(LEDMAN_CMD_OFF, kit[i + 1]);
				}	
				for (i = (KIT_MAX - 1); i >= 0; i-=2) {
					ledman_cmd(LEDMAN_CMD_ON, kit[i]);
					ledman_cmd(LEDMAN_CMD_ON, kit[i + 1]);
					usleep(time);
					ledman_cmd(LEDMAN_CMD_OFF, kit[i]);
					ledman_cmd(LEDMAN_CMD_OFF, kit[i + 1]);
				}
			}		
			break;
		case 2 :
			fprintf(stdout, " KIT 2 \n");
			while(1) {
				for (i = 0; i <= (KIT_MAX - 1); i+=2) {
					ledman_cmd(LEDMAN_CMD_ON, kit[i]);
					ledman_cmd(LEDMAN_CMD_ON, kit[i + 1]);
					usleep(time);
				}	
				for (i = (KIT_MAX - 1); i >= 0; i-=2) {
					ledman_cmd(LEDMAN_CMD_OFF, kit[i]);
					ledman_cmd(LEDMAN_CMD_OFF, kit[i + 1]);
					usleep(time);
				}
			}
			break;
		case 3 :
			fprintf(stdout, " Left 2 Right \n");
			while(1) {
				for (i = 0; i <= L2R_MAX; i++) {
					ledman_cmd(LEDMAN_CMD_ON, left2right[i]);
					usleep(time);
					ledman_cmd(LEDMAN_CMD_OFF, left2right[i]);
				}
			}
			break;
		case 4:
			fprintf(stdout, " Right 2 Left \n");
			while(1) {
				for (i = L2R_MAX; i >= 0; i--) {
					ledman_cmd(LEDMAN_CMD_ON, left2right[i]);
					usleep(time);
					ledman_cmd(LEDMAN_CMD_OFF, left2right[i]);
				}
			}
			break;
		case 5:
		fprintf(stdout, " consecutive \n");
			while(1) {
				for (i = 0; i <= LEDMAN_VPN; i++) {
					ledman_cmd(LEDMAN_CMD_ON, i);
					usleep(time);
					ledman_cmd(LEDMAN_CMD_OFF, i);
				}
			}
			break;

	}
	if ((sequence == 0) && (led != 0)) {
		ledman_cmd(LEDMAN_CMD_ON, led);
		usleep(time);
		ledman_cmd(LEDMAN_CMD_OFF, led);
	}

	ledman_cmd(LEDMAN_CMD_STARTTIMER, 0);
}

void killHandler(void) {
	ledman_cmd(LEDMAN_CMD_STARTTIMER, 0);
	exit(0);
}
