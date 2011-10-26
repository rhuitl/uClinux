/* $Revision: 1.7 $ */
/* $Author: hejl $ */
/* $Header: /home/cvs/lrpStat/src/server/lrpStat.c,v 1.7 2002/05/15 10:13:51 hejl Exp $ */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "lrpStat.h"

char* progName;

int32_t readDataFromHandle(int fHandle, readBuffer_t* pReadBuffer, unsigned long infoType,unsigned long* plSystem, unsigned long* plUser, unsigned long* plNice, unsigned long* plIdle)
{
	char		pcTmpReadBuffer[READ_BUFFER_LENGTH];
	char*		pcTmpBuffer;
	ssize_t		nBytesRead;
	uint32_t	nBufferMinLength;
	int 		i;
	int 		lastPos;

	if (infoType == NET_INFO) {

		while (1) {
			nBytesRead = read(fHandle, pcTmpReadBuffer, READ_BUFFER_LENGTH - 1);
			if (nBytesRead == -1) {
				/* Error */
				return(-1);
			}
			if (nBytesRead == 0) {
				/* EOF */
				break;
			}

			pcTmpReadBuffer[nBytesRead] = 0;
			nBufferMinLength = nBytesRead + strlen(pReadBuffer->pcBuffer) + 1;
			if (nBufferMinLength > pReadBuffer->nBufferLength) {
				/* Current buffer is not large enough. So allocate a new one. */
				pcTmpBuffer = pReadBuffer->pcBuffer;
				pReadBuffer->pcBuffer =
							(char*)malloc(nBufferMinLength * sizeof(char*));
				strcpy(pReadBuffer->pcBuffer, pcTmpBuffer);
				free(pcTmpBuffer);
				pcTmpBuffer	 = NULL;
				pReadBuffer->nBufferLength = nBufferMinLength;
			}
			/* Append the new data at the end */
			strcat(pReadBuffer->pcBuffer, pcTmpReadBuffer);
		}
	} else if (infoType == CPU_INFO) {
		for (i=0;i<=MAX_CPUS;i++) {
			plSystem[i]	= 0;
			plUser[i]	= 0;
			plNice[i]	= 0;
			plIdle[i]	= 0;
		}

		i=0;
		lastPos=0;
		while (1) {

			nBytesRead = read(fHandle, pcTmpReadBuffer, READ_BUFFER_LENGTH - 1);
			if (nBytesRead == -1) {
				/* Error */
				return(-1);
			}
			if (nBytesRead == 0) {
				/* EOF */
				break;
			}

			pcTmpReadBuffer[nBytesRead] = 0;
			nBufferMinLength = nBytesRead + strlen(pReadBuffer->pcBuffer) + 1;

			if (nBufferMinLength > pReadBuffer->nBufferLength) {
				/* Current buffer is not large enough. So allocate a new one. */
				pcTmpBuffer = pReadBuffer->pcBuffer;
				pReadBuffer->pcBuffer =
							(char*)malloc(nBufferMinLength * sizeof(char*));
				strcpy(pReadBuffer->pcBuffer, pcTmpBuffer);
				free(pcTmpBuffer);
				pcTmpBuffer	 = NULL;
				pReadBuffer->nBufferLength = nBufferMinLength;
			}
			/* Append the new data at the end */
			strcat(pReadBuffer->pcBuffer, pcTmpReadBuffer);

			/*  Find the line that Starts with "cpu" */
			for (i=0;i<=MAX_CPUS;i++) {
				pcTmpBuffer = strstr(pReadBuffer->pcBuffer+lastPos, CPU_LINE_PREFIX);
				if (pcTmpBuffer != NULL) {
					pcTmpBuffer += strlen(CPU_LINE_PREFIX);


					if (i==0 && *pcTmpBuffer == ' ') {
						pcTmpBuffer += 2;
						plUser[i]	= strtoul (pcTmpBuffer, &pcTmpBuffer, 0);
						plNice[i]	= strtoul (pcTmpBuffer, &pcTmpBuffer, 0);
						plSystem[i]	= strtoul (pcTmpBuffer, &pcTmpBuffer, 0);
						plIdle[i] 	= strtoul (pcTmpBuffer, &pcTmpBuffer, 0);
						lastPos = (pcTmpBuffer - pReadBuffer->pcBuffer);
				 	} else {
						if (*pcTmpBuffer == '0' + i-1) {
							pcTmpBuffer += 2;
							plUser[i]	= strtoul (pcTmpBuffer, &pcTmpBuffer, 0);
							plNice[i]	= strtoul (pcTmpBuffer, &pcTmpBuffer, 0);
							plSystem[i]	= strtoul (pcTmpBuffer, &pcTmpBuffer, 0);
							plIdle[i] 	= strtoul (pcTmpBuffer, &pcTmpBuffer, 0);
							lastPos = (pcTmpBuffer - pReadBuffer->pcBuffer);
						} else {
							break;
						}
					}
				}

			}
		}
	}
	return(0);
}

void stripWhitespaces(char *src)
{
	char*	dest				= src;
	uint8_t	nPrevWasWhitespace	= 1;

	/* Iterate through the string and replace multiple occurrences of */
	/* whitespaces with one space (and also strip leading whitespaces). */
	for ( ; *src != 0; src++) {
		if (! isspace(*src) || *src == '\n') {
			*dest = *src;
			nPrevWasWhitespace = (*src == '\n');
		}
		else {
			if (nPrevWasWhitespace) continue;
			*dest = ' ';
			nPrevWasWhitespace = 1;
		}
		dest++;
	}
	/* Make it a zero terminated string */
	*dest = 0;
}


#ifdef USE_ISDN
int32_t parseIsdnInfo(int fIsdnInfo, isdninfo_t* pIsdninfo)
{
	char*		pcTmpBuffer;
	char*		pcHelper;
	int16_t		i;
	int32_t		nCurrentDevice, nUsage, nFlags;
	int32_t		pDeviceMapping[ISDN_MAX_CHANNELS];
	int32_t		nRetVal;

	nRetVal = readDataFromHandle(fIsdnInfo, &(pIsdninfo->readBuffer), NET_INFO, NULL, NULL, NULL, NULL);
	if (nRetVal != 0) {
		/* "Real" error condition */
		if (errno != EAGAIN) return(-1);
	}

	/* While there are complete data blocks available */
	while (isCompleteDataBlockFromIsdninfoAvailable(pIsdninfo->readBuffer.pcBuffer)) {
		/* Reset the device infomration */
		for (i=0; i<ISDN_MAX_DRIVERS; i++) {
			pIsdninfo->pDriverInfo[i].state = DEVICE_NON_EXISTENT;
		}

		pcTmpBuffer = pIsdninfo->readBuffer.pcBuffer;
		/* The first two lines contain no information which is relevant to */
		/* us, so we skip them */
		pcTmpBuffer = strchr(pcTmpBuffer, '\n') + 1;
		pcTmpBuffer = strchr(pcTmpBuffer, '\n') + 1;

		/* Sanitycheck we are in the correct line */
		if (strstr(pcTmpBuffer, DEV_ISDNINFO_DRMAP) != pcTmpBuffer) {
				openlog(progName, LOG_PID, LOG_USER);
				syslog(
							LOG_WARNING,
							"Out of sync while reading from isdninfo. (%s).",
							pcTmpBuffer
						);
				closelog();
				return(-1);
		}

		/* Build the "lookup table" which will be used to map the usage */
		/* information to the devices */
		pcTmpBuffer = strstr(pcTmpBuffer, DEV_ISDNINFO_DRMAP) +
					strlen(DEV_ISDNINFO_DRMAP) + 1;

		/* Make the row a zero terminated string. */
		pcHelper = strchr(pcTmpBuffer, '\n');
		*pcHelper = 0;

		for (i=0; i<ISDN_MAX_CHANNELS; i++) {
			nCurrentDevice	= strtol(pcTmpBuffer, &pcTmpBuffer, 32);

			if (errno == ERANGE) {
				openlog(progName, LOG_PID, LOG_USER);
				syslog(LOG_WARNING, "Error while parsing devices (%s).", pcTmpBuffer);
				closelog();
				return(-1);
			}
			if (pcTmpBuffer == 0 && i != ISDN_MAX_CHANNELS - 1) {
				openlog(progName, LOG_PID, LOG_USER);
				syslog(
							LOG_WARNING,
							"Devices underflow. (%d) expected (%d) read.",
							ISDN_MAX_CHANNELS,
							i + 1
						);
				closelog();
				return(-1);
			}
			pDeviceMapping[i] = nCurrentDevice;
			if (nCurrentDevice >= 0) {
				pIsdninfo->pDriverInfo[nCurrentDevice].state = DEVICE_OFFLINE;
			}
		}

		/* Now add the usage information to the device */
		pcTmpBuffer = pcHelper + 1;
		pcTmpBuffer = strstr(pcTmpBuffer, DEV_ISDNINFO_USAGE) +
					strlen(DEV_ISDNINFO_USAGE) + 1;

		for (i=0; i<ISDN_MAX_CHANNELS; i++) {
			nUsage = strtol(pcTmpBuffer, &pcTmpBuffer, 32);

			if (errno == ERANGE) {
				/* Encountered an unexepcted value. Considered as a severe */
				/* error */
				openlog(progName, LOG_PID, LOG_USER);
				syslog(
							LOG_WARNING,
							"Error while parsing usage information (%s).",
							pcTmpBuffer
						);
				closelog();
				return(-1);
			}
			if (pcTmpBuffer == 0 && i != ISDN_MAX_CHANNELS -1) {
				/* Somehow we went out of sync */
				openlog(progName, LOG_PID, LOG_USER);
				syslog(
							LOG_WARNING,
							"Usage info underflow. (%d) expected (%d) read.",
							ISDN_MAX_CHANNELS,
							i + 1
						);
				closelog();
				return(-1);
			}
			if (nUsage > 0) {
				pIsdninfo->pDriverInfo[i].state = DEVICE_TRYING;
			}
		}

		/* Now add the flags information to the device */
		pcTmpBuffer = pcHelper + 1;
		pcTmpBuffer = strstr(pcTmpBuffer, DEV_ISDNINFO_FLAGS) +
					strlen(DEV_ISDNINFO_FLAGS) + 1;

		for (i=0; i<ISDN_MAX_DRIVERS; i++) {
			while (isspace(*pcTmpBuffer)) {
				pcTmpBuffer++;
			}

			if (*pcTmpBuffer == '?') {
				pcTmpBuffer++;
				continue;
			}
			nFlags = strtol(pcTmpBuffer, &pcTmpBuffer, 32);

			if (errno == ERANGE) {
				/* Encountered an unexepcted value. Considered as a severe */
				/* error */
				openlog(progName, LOG_PID, LOG_USER);
				syslog(
							LOG_WARNING,
							"Error while parsing flags information (%s).",
							pcTmpBuffer
						);
				closelog();
				return(-1);
			}
			if (pcTmpBuffer == 0 && i != ISDN_MAX_DRIVERS -1) {
				/* Somehow we went out of sync */
				openlog(progName, LOG_PID, LOG_USER);
				syslog(
							LOG_WARNING,
							"Flags info underflow. (%d) expected (%d) read.",
							ISDN_MAX_DRIVERS,
							i + 1
						);
				closelog();
				return(-1);
			}
			if (nFlags > 0) {
				pIsdninfo->pDriverInfo[i].state = DEVICE_ONLINE;
			}
		}
		pcTmpBuffer = strstr(pcTmpBuffer, DEV_ISDNINFO_IDMAP);
		if (pcTmpBuffer == NULL) {
			*(pIsdninfo->readBuffer.pcBuffer) = 0;
		}
		else {
			strcpy(pIsdninfo->readBuffer.pcBuffer, pcTmpBuffer);
		}
	}
	return(0);
}


uint16_t isCompleteDataBlockFromIsdninfoAvailable(char* pcBuffer)
{
	uint16_t	i;
	char*		pcTmpBuffer = pcBuffer;

	for (i=0; i<DEV_ISDNINFO_NUM_LINES; i++) {
		/* Just jumped onto the last character */
		if (*pcTmpBuffer == 0) return(0);

		pcTmpBuffer = strchr(pcTmpBuffer, '\n');
		if (pcTmpBuffer == NULL) return(0);
		pcTmpBuffer++;
	}
	return(1);
}
#endif

#ifdef USE_ISDN
void sendData(isdninfo_t *isdninfo, char* pszNetInfo, unsigned long* plSystem, unsigned long* plUser, unsigned long* plNice, unsigned long* plIdle)
#else
void sendData(char* pszNetInfo, unsigned long* plSystem, unsigned long* plUser, unsigned long* plNice, unsigned long* plIdle)
#endif
{
	int j;
	struct timeval	tv;
	uint16_t		i;

	/* First line contains protocol version, the current server time and cpu-states */
	gettimeofday(&tv, NULL);
	fprintf(stdout, "%s %lu%03lu %lu %lu %lu %lu\n", PROTOCOL_VERSION, tv.tv_sec, (tv.tv_usec / 1000),plSystem[0], plUser[0], plNice[0], plIdle[0] );

#ifdef USE_ISDN
	for (i=0; i<ISDN_MAX_DRIVERS; i++) {
		if (isdninfo->pDriverInfo[i].state == DEVICE_NON_EXISTENT) {
			continue;
		}
		fprintf(stdout, "%s%d:", ISDN_DEVICE_SUFFIX, i);
		if (isdninfo->pDriverInfo[i].state == DEVICE_OFFLINE) {
			fprintf(stdout, "%s ", DEVICE_OFFLINE_STRING);
		}
		else if (isdninfo->pDriverInfo[i].state == DEVICE_TRYING) {
			fprintf(stdout, "%s ", DEVICE_TRYING_STRING);
		}
		else if (isdninfo->pDriverInfo[i].state == DEVICE_ONLINE) {
			fprintf(stdout, "%s ", DEVICE_ONLINE_STRING);
		}
	}
#endif
	fprintf(stdout, "\n");
	fprintf(stdout, "%s", pszNetInfo);


	/* fix problem on 2.2 Kernels with only one CPU (here, we don't have a cpu0 line
	  in /proc/stat */
	if (plSystem[1]+plUser[1]+plNice[1] == 0 ) {
		plSystem[1] = plSystem[0];
		plUser[1] = plUser[0];
		plNice[1] = plNice[0];
		plIdle[1] = plIdle[0];
	}

	for (j=0;j<MAX_CPUS/2;j++) {
		fprintf(stdout, "cpu%i:",j);	

		for (i=1;i<=2; i++) {
			fprintf(stdout, " %ld",  plSystem[2*j+i]+plUser[2*j+i]+plNice[2*j+i]);
		}	
		for (i=3;i<=8; i++) {
			fprintf(stdout, " 0");
		}
		for (i=1;i<=2; i++) {
			fprintf(stdout, " %ld",  plIdle[2*j+i]);
		}
		for (i=3;i<=8; i++) {
			fprintf(stdout, " 0");
		}
		fprintf(stdout, "\n");		
	}


	fprintf(stdout, "#\n");
	fflush(stdout);
}


int main(int argc, char** argv)
{
	int				fProcNetDev;
	int				fProcStat;
	int				nSleepTime;
	char			*pcSendBuffer;
	int16_t			nExitCode = 0;
	int32_t			nRetVal;
#ifdef USE_ISDN
	int				fIsdnInfo;
	int16_t			i;
	isdninfo_t		isdninfo;
#endif
	readBuffer_t	procNetDevBuffer;
	readBuffer_t	procStatBuffer;
	unsigned long 	plSystem[MAX_CPUS+1];
	unsigned long	plUser[MAX_CPUS+1];
	unsigned long	plNice[MAX_CPUS+1];
	unsigned long	plIdle[MAX_CPUS+1];

	progName = argv[0];
	nSleepTime=1;
	if (argc>1) {
		nSleepTime = atoi(argv[1]);
	}
	if (nSleepTime<1) nSleepTime=1;

#ifdef USE_ISDN
	/* Open the isdninfo device */
	fIsdnInfo = open(DEV_ISDNINFO, O_RDONLY);
	if (fIsdnInfo == -1) {
		/* Something went wrong while opening the "file". All we can do */
		/* is to abort the program; someday we might use an error */
		/* protocol. */
		openlog(progName, LOG_PID, LOG_USER);
		syslog(LOG_WARNING, "Unable to open %s. (%m).", DEV_ISDNINFO);
		closelog();
		exit(1);
	}
	/* Make the filehandle nonblocking */
	if (fcntl(fIsdnInfo, F_SETFL, O_NONBLOCK) == -1) {
		openlog(progName, LOG_PID, LOG_USER);
		syslog(LOG_WARNING,"Unable to set %s non-blocking. (%m).",DEV_ISDNINFO);
		closelog();
		exit(1);
	}
#endif

	/* Initialize the data buffers */;
	procNetDevBuffer.pcBuffer
				= (char*)malloc((READ_BUFFER_LENGTH + 1) * sizeof(char*));
	procNetDevBuffer.nBufferLength = READ_BUFFER_LENGTH;

	procStatBuffer.pcBuffer
				= (char*)malloc((READ_BUFFER_LENGTH + 1) * sizeof(char*));
	procStatBuffer.nBufferLength = READ_BUFFER_LENGTH;

#ifdef USE_ISDN
	/* Initialize the isdninfo structure */
	isdninfo.readBuffer.pcBuffer =
				(char*)malloc((READ_BUFFER_LENGTH + 1) * sizeof(char*));
	isdninfo.readBuffer.nBufferLength = READ_BUFFER_LENGTH;
	for (i=0; i<ISDN_MAX_DRIVERS; i++) {
		isdninfo.pDriverInfo[i].state = DEVICE_NON_EXISTENT;
	}
#endif

	while (1) {
#ifdef USE_ISDN
		nRetVal = parseIsdnInfo(fIsdnInfo, &isdninfo);
		if (nRetVal != 0) break;
#endif

		/* Open the "file" in the proc system, which provides us with the */
		/* required information about the network devices */
		fProcNetDev = open(PROC_NET_DEV, O_RDONLY);
		if (fProcNetDev == -1) {
			/* Something went wrong while opening the "file". */
			openlog(progName, LOG_PID, LOG_USER);
			syslog(LOG_WARNING, "Unable to open %s. (%m).", PROC_NET_DEV);
			closelog();
			nExitCode = 1;
			break;
		}

		/* Now slurp in the information */
		nRetVal = readDataFromHandle(fProcNetDev, &procNetDevBuffer, NET_INFO, NULL, NULL, NULL, NULL);
		if (nRetVal != 0) {
			openlog(progName, LOG_PID, LOG_USER);
			syslog(LOG_WARNING, "Unable to read from %s. (%m).", PROC_NET_DEV);
			closelog();
			nExitCode = 1;
			break;
		}
		close(fProcNetDev);

		/* Open the "file" in the proc system, which provides us with the */
		/* required information about the cpu state */
		fProcStat = open(PROC_STAT, O_RDONLY);
		if (fProcStat == -1) {
			/* Something went wrong while opening the "file". */
			openlog(progName, LOG_PID, LOG_USER);
			syslog(LOG_WARNING, "Unable to open %s. (%m).", PROC_STAT);
			closelog();
			nExitCode = 1;
			break;
		}

		/* Now slurp in the information */
		nRetVal = readDataFromHandle(fProcStat, &procStatBuffer, CPU_INFO, plSystem, plUser, plNice, plIdle );
		if (nRetVal != 0) {
			openlog(progName, LOG_PID, LOG_USER);
			syslog(LOG_WARNING, "Unable to read from %s. (%m).", PROC_STAT);
			closelog();
			nExitCode = 1;
			break;
		}
		close(fProcStat);


		/* Remove the first two lines */
		pcSendBuffer = strchr(procNetDevBuffer.pcBuffer, '\n') + 1;
		pcSendBuffer = strchr(pcSendBuffer, '\n') + 1;
		stripWhitespaces(pcSendBuffer);

#ifdef USE_ISDN
		sendData(&isdninfo, pcSendBuffer, plSystem, plUser, plNice, plIdle);
#else
		sendData(pcSendBuffer, plSystem, plUser, plNice, plIdle);
#endif
		*procNetDevBuffer.pcBuffer = 0;
		*procStatBuffer.pcBuffer = 0;

		sleep(nSleepTime);
	}
	free(procNetDevBuffer.pcBuffer);
#ifdef USE_ISDN
	free(isdninfo.readBuffer.pcBuffer);
#endif
	exit(nExitCode);
}
