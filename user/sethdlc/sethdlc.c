#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/hdlc.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>


struct ifreq req;		/* for ioctl */



void error(const char *format, ...) __attribute__ ((noreturn));

void error(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fprintf(stderr, "%s: ", req.ifr_name);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(1);
}



typedef struct {
	const char *name;
	const int value;
} parsertab;



int parser(const char *name, parsertab *tab)
{
	int i;
	for (i = 0; tab[i].name; i++) {
		if (!strcmp(tab[i].name, name)) {
			req.ifr_ifru.ifru_ivalue = tab[i].value;
			return 0;
		}
	}
	return -1;		/* Not found */
}



void run_board(const int sock, const char *filename)
{
	__u32 length;
	FILE *fw;

	fw=fopen(filename, "rb");
	if (fw==NULL)
		error("Unable to open firmware file: %s\n", strerror(errno));

	fseek(fw, 0, SEEK_END);
	length=ftell(fw);
	fseek(fw, 0, SEEK_SET);
	req.ifr_data=malloc(length+sizeof(__u32));
	if (req.ifr_data==NULL) {
		fclose(fw);
		error("Out of memory\n");
	}

	*(__u32*)req.ifr_data = length;
	if (fread(req.ifr_data+sizeof(__u32), 1, length, fw)!=length) {
		fclose(fw);
		error("Error reading firmware file: %s\n", strerror(errno));
	}

	fclose(fw);

	if (ioctl(sock, HDLCRUN, &req))
		error("Running failed: %s\n", strerror(errno));

	free(req.ifr_data);
}



void set_clock(const int sock, int *arg, int argc, char *argv[])
{
	int rate = 0, type = 0;

	parsertab tab[]={{ "ext", CLOCK_EXT },
			 { "int", CLOCK_INT },
			 { "txint", CLOCK_TXINT },
			 { "txfromrx", CLOCK_TXFROMRX },
			 { NULL }};

	if (!(argc > *arg))
		error("Missing clock rate/type\n");

	while((rate == 0 || type == 0) && argc > *arg) {
		int speed;
		char test;
		if ((rate == 0) &&
		    (sscanf(argv[*arg], "%i%c", &speed, &test) == 1)) {
			req.ifr_ifru.ifru_ivalue = speed;
			if (ioctl(sock, HDLCSCLOCKRATE, &req))
				error("Unable to set clock rate: %s\n",
				      strerror(errno));

			if (req.ifr_ifru.ifru_ivalue != speed)
				printf("%s: Using clock rate %i bps\n",
				       req.ifr_name,
				       req.ifr_ifru.ifru_ivalue);
			rate = 1;
			(*arg)++;
			continue;
		}

		if ((type == 0) && !parser(argv[*arg], tab)) {
			if (ioctl(sock, HDLCSCLOCK, &req))
				error("Unable to set clock: %s\n",
				      strerror(errno));
			type = 1;
			(*arg)++;
			continue;
		}

		break;
	}

	if (rate == 0 && type == 0)
			error("Invalid clock rate/type %s\n", argv[*arg]);
}



void fr_pvc(const int sock, char *arg, const int creat_del)
{
	int dlci;
	char test;

	if (sscanf(arg, "%u%c", &dlci, &test)==1)
		if (dlci>0 && dlci<1023) {
			req.ifr_ifru.ifru_ivalue = dlci * creat_del;
			if (ioctl(sock, HDLCPVC, &req))
				error("Unable to %s PVC: %s\n",
				      (creat_del == 1) ? "create" : "delete",
				      strerror(errno));
			return;
		}

	error("Invalid dlci %s\n", arg);
}



void show_port(const int sock)
{
	char *proto, *dce = "", *soft = "", *line, *loopback = "";
	char *clock, rate[64] = "", slots[64] = "";
	int clkint = 0;

	if (ioctl(sock, HDLCGMODE, &req))
		error("Error getting protocol: %s\n", strerror(errno));
	switch(req.ifr_ifru.ifru_ivalue & ~(MODE_DCE | MODE_SOFT)) {
	case MODE_NONE: proto = "none"; break;
	case MODE_HDLC: proto = "raw HDLC"; break;
	case MODE_CISCO: proto = "Cisco HDLC"; break;
	case MODE_PPP: proto = "PPP"; break;
	case MODE_FR_ANSI: proto = "Frame Relay (ANSI LMI)"; break;
	case MODE_FR_CCITT: proto = "Frame Relay (CCITT LMI)"; break;
	case MODE_X25: proto = "X.25"; break;
	default: proto = "unknown - upgrade sethdlc"; break;
	}

	if (req.ifr_ifru.ifru_ivalue & MODE_DCE)
		dce = " (DCE)";

	if (req.ifr_ifru.ifru_ivalue & MODE_SOFT)
		soft = " (soft)";

	if (ioctl(sock, HDLCGLINE, &req))
		error("Error getting physical interface: %s\n",
		      strerror(errno));
	switch(req.ifr_ifru.ifru_ivalue & ~LINE_LOOPBACK) {
	case LINE_DEFAULT: line = "default"; break;
	case LINE_V35: line = "V.35"; break;
	case LINE_RS232: line = "RS232"; break;
	case LINE_X21: line = "X.21"; break;
	case LINE_T1: line = "T1"; break;
	case LINE_E1: line = "E1"; break;
	default: line = "unknown - upgrade sethdlc"; break;
	}

	if (req.ifr_ifru.ifru_ivalue & LINE_LOOPBACK)
		loopback = " (loopback)";

	if (ioctl(sock, HDLCGCLOCK, &req))
		clock = "default"; /* Not supported */
	else
		switch(req.ifr_ifru.ifru_ivalue) {
		case CLOCK_EXT: clock = "external"; break;
		case CLOCK_INT: clock = "internal"; clkint = 1; break;
		case CLOCK_TXINT: clock = "TX internal RX external";
			clkint = 1; break;
		case CLOCK_TXFROMRX: clock = "TX derived from external RX";
			break;
		default: clock = "unknown - upgrade sethdlc"; break;
		}

	if (clkint) {
		if (ioctl(sock, HDLCGCLOCKRATE, &req))
			error("Error getting clock rate: %s\n",
			      strerror(errno));
		else
			sprintf(rate, " rate: %i bps",
				req.ifr_ifru.ifru_ivalue);
	}

	if (!ioctl(sock, HDLCGSLOTMAP, &req)) {
		int i, j, mask;

		strcpy(slots, "\tslots in use: ");
		for (i = j = strlen(slots), mask = 1 << 31;
		     i < 32 + j;
		     i++, mask >>= 1)
			slots[i] = (req.ifr_ifru.ifru_ivalue & mask) ?
				'1' : '0';
		slots[i++] = '\n';
		slots[i] = '\x0';
	}

	printf("%s:\tmode: %s%s%s
\tline: %s%s
\tclock: %s%s
%s\n", req.ifr_name, proto, dce, soft, line, loopback, clock, rate, slots);
}



void usage(void)
{
	error("\nsethdlc version 1.01 for Linux 2.4

Copyright (C) 2000 Krzysztof Halasa <khc@pm.waw.pl>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Usage: sethdlc interface command [parameters] ...

commands:
\trun <firmware_file_name>
\tclock (<rate> | int | ext | txint | txfromrx )
\tmode [soft] [dce] (hdlc | cisco | ppp | [fr-]ansi | [fr-]ccitt | x25)
\tv35[-lb] | rs232[-lb] | x21[-lb] | t1[-lb] | e1[-lb] | lb | default
\tslotmap <map>
\t(create | delete) <dlci>

Some commands and parameters may not be supported by some drivers or hardware
");
	exit(0);
}



int main(int argc, char *argv[])
{
	int sock, arg = 2;
	parsertab lines[] = {{ "v35", LINE_V35 },
			     { "v35-lb", LINE_V35 | LINE_LOOPBACK },
			     { "rs232", LINE_RS232 },
			     { "rs232-lb", LINE_RS232 | LINE_LOOPBACK },
			     { "x21", LINE_X21 },
			     { "x21-lb", LINE_X21 | LINE_LOOPBACK },
			     { "t1", LINE_T1 },
			     { "t1-lb", LINE_T1 | LINE_LOOPBACK },
			     { "e1", LINE_E1 },
			     { "e1-lb", LINE_E1 | LINE_LOOPBACK },
			     { "default", LINE_DEFAULT },
			     { "lb", LINE_LOOPBACK },
			     { "loopback", LINE_LOOPBACK },
			     { NULL }};

	if (argc <= 1)
		usage();
  
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock<0)
		error("Unable to create socket: %s\n", strerror(errno));
  
	strcpy(req.ifr_name, argv[1]); /* Device name */

	if (argc == 2) {
		show_port(sock);
		exit(0);
	}

	while (argc > arg) {
		if (!strcmp(argv[arg], "clock")) {
			arg++;
			set_clock(sock, &arg, argc, argv);
			continue;
		}
    
		if (!parser(argv[arg], lines)) {
			if (ioctl(sock, HDLCSLINE, &req))
				error("Unable to set physical interface: %s\n",
				      strerror(errno));
			arg++;
			continue;
		}
    
		if (argc > arg+1 && !strcmp(argv[arg], "create")) /* PVC */ {
			fr_pvc(sock, argv[++arg], 1);
			arg++;
			continue;
		}

		if (argc > arg+1 && !strcmp(argv[arg], "delete")) /* PVC */ {
			fr_pvc(sock, argv[++arg], -1);
			arg++;
			continue;
		}

		/* Download firmware and run board */
		if (argc > arg+1 && !strcmp(argv[arg], "run")) {
			run_board(sock, argv[++arg]);
			arg++;
			continue;
		}
    
		/* Set mode */
		if (argc > arg+1 && !strcmp(argv[arg], "mode")) {
			int mode = 0;
			arg++;

			if (argc > arg+1 && !strcmp(argv[arg], "soft")) {
				mode |= MODE_SOFT;
				arg++;
			}

			if (argc > arg+1 && !strcmp(argv[arg], "dce")) {
				mode |= MODE_DCE;
				arg++;
			}

			if (!strcmp(argv[arg], "hdlc"))
				mode |= MODE_HDLC;
			else if (!strcmp(argv[arg], "cisco"))
				mode |= MODE_CISCO;
			else if (!strcmp(argv[arg], "ppp"))
				mode |= MODE_PPP;
			else if (!strcmp(argv[arg], "ansi") ||
				 !strcmp(argv[arg], "fr_ansi") ||
				 !strcmp(argv[arg], "fr-ansi"))
				mode |= MODE_FR_ANSI;
			else if (!strcmp(argv[arg], "ccitt")||
				 !strcmp(argv[arg], "fr_ccitt")||
				 !strcmp(argv[arg], "fr-ccitt"))
				mode |= MODE_FR_CCITT;
			else if (!strcmp(argv[arg], "x25"))
				mode |= MODE_X25;
			else
				mode = 0;

			if (mode) {
				req.ifr_ifru.ifru_ivalue = mode;
				if (ioctl(sock, HDLCSMODE, &req))
					error("Error setting mode: %s\n",
					      strerror(errno));
				arg++;
				continue;
			}
		}

		error("\nInvalid parameter: %s\n", argv[arg]);
	}

	close(sock);
	exit(0);
}
