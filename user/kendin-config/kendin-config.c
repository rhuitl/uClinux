/*
 * Small program for configuring the Micrel Kendin KS8995M over QSPI
 *
 * Copyright (c) 2003 Miriam Technologies Inc. <uclinux@miriamtech.com>
 * Copyright (c) 2003 Engineering Technologies Canada Ltd. (engtech.ca)
 * Copyright (c) 2003 Travis Griggs <tgriggs@keyww.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <getopt.h>

#ifdef __uClinux__
#include <asm/coldfire.h>
#include <asm/mcfqspi.h>
#include <asm/mcfsim.h>
#endif

uint8_t port = 1;
uint32_t cpol = 1;
uint32_t cpha = 1;
int32_t serialPort;
char * programName;

typedef void(*commandHandler)(uint32_t argCount, char** arguments);

static uint8_t spiRead(uint8_t registerIndex)
{
	uint8_t registerValue = 0;
	uint32_t count;

#ifdef __uClinux__
	qspi_read_data readData;

	readData.buf[0] = 3; //2r11 is the read command
	readData.buf[1] = registerIndex;
	readData.length = 2;
	readData.loop = 0;
	if (ioctl(serialPort, QSPIIOCS_READDATA, &readData)) perror("QSPIIOCS_READDATA"); 
	count = read(serialPort, &registerValue, 1);
	if(count != 1) perror("read");
#endif
	return registerValue;
}

static void spiWrite(uint8_t registerIndex, uint8_t registerValue)
{
	uint8_t sendBuffer[3];
	uint32_t count;

	sendBuffer[0] = 2; //2r10 is the write command
	sendBuffer[1] = registerIndex;
	sendBuffer[2] = registerValue;

#ifdef __uClinux__
	count = write(serialPort, sendBuffer, 3);
	if(count != 3) perror("write");
#endif
}

void commandGet(uint32_t argumentCount, char** arguments)
{
	uint8_t registerIndex;

	if(argumentCount != 1) {
		printf("usage: %s [options] g[et] registerIndex\n", programName);
		return;
	}
	registerIndex = atoi(arguments[0]);
	printf("get registerIndex(%d) --> %X\n", registerIndex, spiRead(registerIndex));
}

void commandSet(uint32_t argumentCount, char** arguments)
{
	uint8_t registerIndex;
	uint32_t value;

	if(argumentCount != 2) {
		printf("usage: %s [options] s[et] registerIndex value\n", programName);
		return;
	}
	registerIndex = atoi(arguments[0]);
	sscanf(arguments[1], "%x", &value);
	spiWrite(registerIndex, value);
	printf("set %d = %X\n", registerIndex, value);
}

void commandEnable(uint32_t argumentCount, char** arguments)
{
	if(argumentCount != 0) {
		printf("usage: %s [options] e[nable]\n", programName);
		return;
	}

	spiWrite(1, 1);
	printf("enabled\n");
}

typedef struct {
	char * commandName;
	commandHandler theCommand;
} Command, *pCommand;

Command commands[] = {
	{"get", commandGet},
	{"set", commandSet},
	{"enable", commandEnable},
	{NULL, NULL}};

static int32_t parse_args(int argc, char **argv) {
	static const struct option options[] = {
		{"port", 1, 0, 'p'},
		{"cpol", 1, 0, 'l'},
		{"cpha", 1, 0, 'a'},
		{ 0, 0, 0, 0 }
 	};

 	int32_t c, index, consumedArgs = 0;
				 
 	while((c = getopt_long(argc, argv, "p:l:a:", options, &index)) != -1) {
 		switch(c) {
			case 'p': port = atoi(optarg); consumedArgs+=2; break;
			case 'l': cpol = (atoi(optarg) != 0); consumedArgs+=2; break;
			case 'a': cpha = (atoi(optarg) != 0); consumedArgs+=2; break;
			default:
				printf("unknown option\n");
				break;
		}
	}
	return consumedArgs;
}
	 
int main (int argc, char** argv)
{
	int32_t baudRate;
	int32_t lessArgc;
	pCommand eachCommand, foundCommand = NULL;
	char* commandName;
	
	char devicePath[BUFSIZ];

	programName = argv[0];

	lessArgc = parse_args(argc, argv);

    sprintf(devicePath, "/dev/qspi%d", port);

	// printf("%s --port %d --cpol %d --cpha %d\n", argv[0], port, cpol, cpha);

#ifdef __uClinux__
    serialPort = open(devicePath, O_RDWR);
	if(serialPort < 0) {
        perror("open");
        exit(1);
    }

	if(ioctl(serialPort, QSPIIOCS_DOUT_HIZ, 0)) perror("QSPIIOCS_DOUT_HIZ");
	if(ioctl(serialPort, QSPIIOCS_BITS, 8)) perror("QSPIIOCS_BITS");
	if(ioctl(serialPort, QSPIIOCS_CPOL, cpol)) perror("QSPIIOCS_CPOL");
	if(ioctl(serialPort, QSPIIOCS_CPHA, cpha)) perror("QSPIIOCS_CPHA");
	baudRate = 8; // (MCF_CLK / (2 * 5000000)) = 4.8, rounded up to 8
	if(ioctl(serialPort, QSPIIOCS_BAUD, baudRate)) perror("QSPIIOCS_BAUD");
#endif

	commandName = argv[1 + lessArgc];
	for(eachCommand = commands; eachCommand->commandName != NULL; eachCommand++) {
		if(strncmp(eachCommand->commandName, commandName, strlen(commandName)) == 0) {
			if(foundCommand) break;
			else {
				foundCommand = eachCommand;
			}
		}
	}
	if(foundCommand) {
		foundCommand->theCommand(argc - 2 - lessArgc, argv + 2 + lessArgc);
	} else {
		printf("Unknown command: %s\n", commandName);
	}

	return 0;
}
