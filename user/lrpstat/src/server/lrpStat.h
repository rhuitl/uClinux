/* $Revision: 1.4 $ */
/* $Author: hejl $ */
/* $Header: /home/cvs/lrpStat/src/server/lrpStat.h,v 1.4 2002/05/15 10:13:51 hejl Exp $ */

/*
Protocol format for protocol-version 1.20:
Line 1: ProtocolVersion timestamp cpuSystem cpuUser cpuNice cpuIdle
Line 2: ISDNDeviceName1:ONLINE|OFFLINE ISDNDeviceName2:ONLINE|OFFLINE ...
Line 3..n: deviceName:InBytes InPackets InErrors InDrop InFifo InFrame InCompressed InMulticast OutBytes OutPackets OutErrors OutDrop OutFifo OutCollisions OutCarrier OutCompressed

*/

#ifndef _lrp_stat_h
	#define _lrp_stat_h

	/* PROTOCOL Version: major minor patchlevel*/
	#define PROTOCOL_VERSION        "130"

	#define PROC_NET_DEV			"/proc/net/dev"
	#define PROC_STAT				"/proc/stat"
	#define READ_BUFFER_LENGTH		4096
	#define NET_INFO				1
	#define CPU_INFO				2
	#define CPU_LINE_PREFIX			"cpu"
	#define MAX_CPUS				4

	#define ISDN_DEVICE_SUFFIX	"ippp"

	typedef struct readBuffer_st {
		uint32_t	nBufferLength;
		char*		pcBuffer;
	} readBuffer_t;


	#ifdef USE_ISDN

		#include <linux/isdn.h>

		#define DEV_ISDNINFO			"/dev/isdninfo"
		#define DEV_ISDNINFO_NUM_LINES	6
		#define DEV_ISDNINFO_IDMAP		"idmap:"
		#define DEV_ISDNINFO_DRMAP		"drmap:"
		#define DEV_ISDNINFO_USAGE		"usage:"
		#define DEV_ISDNINFO_FLAGS		"flags:"
		#define DEV_ISDNINFO_PHONE		"phone:"

		#define DEVICE_NON_EXISTENT	0
		#define DEVICE_OFFLINE		1
		#define DEVICE_TRYING		2
		#define DEVICE_ONLINE		3

		#define DEVICE_OFFLINE_STRING	"OFFLINE"
		#define DEVICE_TRYING_STRING	"TRYING"
		#define DEVICE_ONLINE_STRING	"ONLINE"

		typedef struct isdnDriverInfo_st {
			uint32_t	state;
		} isdnDriverInfo_t;

		typedef struct isdninfo_st {
			readBuffer_t		readBuffer;
			isdnDriverInfo_t	pDriverInfo[ISDN_MAX_DRIVERS];
		} isdninfo_t;

		void sendData(isdninfo_t *isdninfo, char* pszNetInfo, unsigned long* lSystem, unsigned long* lUser, unsigned long* lNice, unsigned long* lIdle);

		int32_t parseIsdnInfo(int fIsdnInfo, isdninfo_t* isdninfo);
		uint16_t isCompleteDataBlockFromIsdninfoAvailable(char* pcBuffer);

	#else
		void sendData(char* pszNetInfo, unsigned long* lSystem, unsigned long* lUser, unsigned long* lNice, unsigned long* lIdle);
	#endif


	int32_t readDataFromHandle(int fHandle, readBuffer_t* pReadBuffer, unsigned long infoType,unsigned long* plSystem, unsigned long* plUser, unsigned long* plNice, unsigned long* plIdle);
	void stripWhitespaces(char *src);


#endif



