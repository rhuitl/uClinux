/* src/prism2/download/prism2dl.c
*
* user utility for downloading prism2 images
*
* Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
*   This software is distributed on an "AS
*   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
*   implied. See the License for the specific language governing
*   rights and limitations under the License.
*
*   This software is NOT distributed under an Open Source license.
*   If you received it without a direct license from AbsoluteValue 
*   Systems, Inc. then you are not a licensed user and are violating
*   AbsoluteValue Systems rights under copyright law.
*   
* --------------------------------------------------------------------
*
* Inquiries regarding this software and AbsoluteValue Systems products
* and service can be made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*
* Portions of the development of this software were funded by 
* Intersil Corporation as part of PRISM(R) chipset product development.
*
* --------------------------------------------------------------------
*/

/*================================================================*/
/* System Includes */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <endian.h>
#include <byteswap.h>

/*================================================================*/
/* Project Includes */

#include <wlan/wlan_compat.h>
#include <wlan/version.h>
#include <wlan/p80211hdr.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211metamsg.h>
#include <wlan/p80211msg.h>
#include <wlan/p80211metadef.h>
#include <wlan/p80211metastruct.h>
#include <wlan/p80211ioctl.h>
#include <prism2/hfa384x.h>

/* Redefine macros for endianness to avoid using kernel headers */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define hfa384x2host_16(n) (n)
#define hfa384x2host_32(n) (n)
#define host2hfa384x_16(n) (n)
#define host2hfa384x_32(n) (n)
#else
#define hfa384x2host_16(n) bswap_16(n)
#define hfa384x2host_32(n) bswap_32(n)
#define host2hfa384x_16(n) bswap_16(n)
#define host2hfa384x_32(n) bswap_32(n)
#endif

/*================================================================*/
/* Local Constants */

#define APPNAME			"prism2dl"
#define APPNAME_MAX		30
#define ADDPDRFILES_MAX		10
#define RAMFILES_MAX		10
#define FLASHFILES_MAX		10

#define S3DATA_MAX		5000
#define S3PLUG_MAX		200
#define S3CRC_MAX		200
#define S3INFO_MAX		50
#define SREC_LINE_MAX		264
#define S3LEN_TXTOFFSET		2
#define S3LEN_TXTLEN		2
#define S3ADDR_TXTOFFSET	4
#define S3ADDR_TXTLEN		8
#define S3DATA_TXTOFFSET	12
/*S3DATA_TXTLEN			variable, depends on len field */
/*S3CKSUM_TXTOFFSET		variable, depends on len field */
#define S3CKSUM_TXTLEN		2
#define SERNUM_LEN_MAX		12

#define S3PLUG_ITEMCODE_TXTOFFSET	(S3DATA_TXTOFFSET)
#define S3PLUG_ITEMCODE_TXTLEN		8
#define S3PLUG_ADDR_TXTOFFSET		(S3DATA_TXTOFFSET+8)
#define S3PLUG_ADDR_TXTLEN		8
#define S3PLUG_LEN_TXTOFFSET		(S3DATA_TXTOFFSET+16)
#define S3PLUG_LEN_TXTLEN		8

#define S3CRC_ADDR_TXTOFFSET		(S3DATA_TXTOFFSET)
#define S3CRC_ADDR_TXTLEN		8
#define S3CRC_LEN_TXTOFFSET		(S3DATA_TXTOFFSET+8)
#define S3CRC_LEN_TXTLEN		8
#define S3CRC_DOWRITE_TXTOFFSET		(S3DATA_TXTOFFSET+16)
#define S3CRC_DOWRITE_TXTLEN		8

#define S3INFO_LEN_TXTOFFSET		(S3DATA_TXTOFFSET)
#define S3INFO_LEN_TXTLEN		4
#define S3INFO_TYPE_TXTOFFSET		(S3DATA_TXTOFFSET+4)
#define S3INFO_TYPE_TXTLEN		4
#define S3INFO_DATA_TXTOFFSET		(S3DATA_TXTOFFSET+8)
/* S3INFO_DATA_TXTLEN			variable, depends on INFO_LEN field */

#define S3ADDR_PLUG		(0xff000000UL)
#define S3ADDR_CRC		(0xff100000UL)
#define S3ADDR_INFO		(0xff200000UL)

#define PDAFILE_LINE_MAX	1024

#define CHUNKS_MAX		100

#define WRITESIZE_MAX		4096

/*================================================================*/
/* Local Macros */


/*================================================================*/
/* Local Types */

typedef struct s3datarec
{
	UINT32	len;
	UINT32	addr;
	UINT8	checksum;
	UINT8	*data;
} s3datarec_t;

typedef struct s3plugrec
{
	UINT32	itemcode;
	UINT32	addr;
	UINT32	len;
} s3plugrec_t;

typedef struct s3crcrec
{
	UINT32	addr;
	UINT32	len;
	UINT	dowrite;
} s3crcrec_t;

typedef struct s3inforec
{
	UINT16	len;
	UINT16	type;
	union {
		hfa384x_compident_t	version;
		hfa384x_caplevel_t	compat;
		UINT16			buildseq;
		hfa384x_compident_t	platform;
	}	info;
} s3inforec_t;

typedef struct pda
{
	UINT8		buf[HFA384x_PDA_LEN_MAX];
	hfa384x_pdrec_t	*rec[HFA384x_PDA_RECS_MAX];
	UINT		nrec;
} pda_t;

typedef struct imgchunk
{
	UINT32	addr;	/* start address */
	UINT32	len;	/* in bytes */
	UINT16	crc;	/* CRC value (if it falls at a chunk boundary) */
	UINT8	*data;
} imgchunk_t;

/*================================================================*/
/* Local Static Definitions */

/*----------------------------------------------------------------*/
/* App support */
char	appname[APPNAME_MAX + 1];
char	*fullname;
char	devname[16];

/*----------------------------------------------------------------*/
/* option flags */
/* GENERAL options */
int	opt_status = 0;		/* -s => show status and exit */
int	opt_verbose = 0;	/* -v => boolean, verbose operation */
int	opt_nowrite = 0;	/* -n => boolean, process all data-but don't download */
int	opt_debug = 0;		/* -d => boolean, process all data-but don't download */
int	opt_generate = 0;	/* -g => boolean, if -s or -d output is in pdr and srec file format */
int	opt_dumpchunks = 0;	/* -D => boolean, dump the imgchunks after plugging and crc */


/* IMAGEFILE options */
int	opt_ramloadcnt = 0;	/* -r => boolean & count of ram filenames */
char	rfname[RAMFILES_MAX][FILENAME_MAX+1]; /* -r filenames */

int	opt_flashloadcnt = 0;	/* -f => boolean & count of flash filenames */
char	ffname[FLASHFILES_MAX][FILENAME_MAX+1]; /* -f filenames */

/* PDA options */
int	opt_addpdrcnt = 0;		/* -a => boolean & count of addfiles */
char	addpdrfname[ADDPDRFILES_MAX][FILENAME_MAX+1]; /* -a filenames */

int	opt_newpda = 0;			/* -p => boolean for whole new PDA */
char	newpdafname[FILENAME_MAX+1];	/* -p filename */

int	opt_macaddr = 0;		/* -m => boolean for cmdline MAC address */
UINT8	macaddr[WLAN_ADDR_LEN];		/* -m mac address */

int	opt_sernum = 0;			/* -S => boolean for cmdline serial # */
char	sernum[SERNUM_LEN_MAX+1];	/* -S serial # string */

int	opt_pdaloc = 0;			/* -l => pda location */
					/* -l address */

char	opts[] = "svVndDgr:f:a:p:m:S:l:";

/*----------------------------------------------------------------*/
/* s-record image processing */

/* Data records */
UINT		ns3data = 0;
s3datarec_t	s3data[S3DATA_MAX];

/* Plug records */
UINT		ns3plug = 0;
s3plugrec_t	s3plug[S3PLUG_MAX];

/* CRC records */
UINT		ns3crc = 0;
s3crcrec_t	s3crc[200];

/* Info records */
UINT		ns3info = 0;
s3inforec_t	s3info[50];

/* S7 record (there _better_ be only one) */
UINT32		startaddr;

/* Load image chunks */
UINT		nfchunks;
imgchunk_t	fchunk[CHUNKS_MAX];

/* Note that for the following pdrec_t arrays, the len and code */
/*   fields are stored in HOST byte order. The mkpdrlist() function */
/*   does the conversion.  */
/*----------------------------------------------------------------*/
/* PDA, built from [card|newfile]+[addfile1+addfile2...] */

pda_t		pda;
hfa384x_compident_t nicid;
hfa384x_caplevel_t  rfid;
hfa384x_caplevel_t  macid;
hfa384x_caplevel_t  priid;

const UINT16 crc16tab[256] =
{
	0x0000, 0xc0c1, 0xc181, 0x0140, 0xc301, 0x03c0, 0x0280, 0xc241,
	0xc601, 0x06c0, 0x0780, 0xc741, 0x0500, 0xc5c1, 0xc481, 0x0440,
	0xcc01, 0x0cc0, 0x0d80, 0xcd41, 0x0f00, 0xcfc1, 0xce81, 0x0e40,
	0x0a00, 0xcac1, 0xcb81, 0x0b40, 0xc901, 0x09c0, 0x0880, 0xc841,
	0xd801, 0x18c0, 0x1980, 0xd941, 0x1b00, 0xdbc1, 0xda81, 0x1a40,
	0x1e00, 0xdec1, 0xdf81, 0x1f40, 0xdd01, 0x1dc0, 0x1c80, 0xdc41,
	0x1400, 0xd4c1, 0xd581, 0x1540, 0xd701, 0x17c0, 0x1680, 0xd641,
	0xd201, 0x12c0, 0x1380, 0xd341, 0x1100, 0xd1c1, 0xd081, 0x1040,
	0xf001, 0x30c0, 0x3180, 0xf141, 0x3300, 0xf3c1, 0xf281, 0x3240,
	0x3600, 0xf6c1, 0xf781, 0x3740, 0xf501, 0x35c0, 0x3480, 0xf441,
	0x3c00, 0xfcc1, 0xfd81, 0x3d40, 0xff01, 0x3fc0, 0x3e80, 0xfe41,
	0xfa01, 0x3ac0, 0x3b80, 0xfb41, 0x3900, 0xf9c1, 0xf881, 0x3840,
	0x2800, 0xe8c1, 0xe981, 0x2940, 0xeb01, 0x2bc0, 0x2a80, 0xea41,
	0xee01, 0x2ec0, 0x2f80, 0xef41, 0x2d00, 0xedc1, 0xec81, 0x2c40,
	0xe401, 0x24c0, 0x2580, 0xe541, 0x2700, 0xe7c1, 0xe681, 0x2640,
	0x2200, 0xe2c1, 0xe381, 0x2340, 0xe101, 0x21c0, 0x2080, 0xe041,
	0xa001, 0x60c0, 0x6180, 0xa141, 0x6300, 0xa3c1, 0xa281, 0x6240,
	0x6600, 0xa6c1, 0xa781, 0x6740, 0xa501, 0x65c0, 0x6480, 0xa441,
	0x6c00, 0xacc1, 0xad81, 0x6d40, 0xaf01, 0x6fc0, 0x6e80, 0xae41,
	0xaa01, 0x6ac0, 0x6b80, 0xab41, 0x6900, 0xa9c1, 0xa881, 0x6840,
	0x7800, 0xb8c1, 0xb981, 0x7940, 0xbb01, 0x7bc0, 0x7a80, 0xba41,
	0xbe01, 0x7ec0, 0x7f80, 0xbf41, 0x7d00, 0xbdc1, 0xbc81, 0x7c40,
	0xb401, 0x74c0, 0x7580, 0xb541, 0x7700, 0xb7c1, 0xb681, 0x7640,
	0x7200, 0xb2c1, 0xb381, 0x7340, 0xb101, 0x71c0, 0x7080, 0xb041,
	0x5000, 0x90c1, 0x9181, 0x5140, 0x9301, 0x53c0, 0x5280, 0x9241,
	0x9601, 0x56c0, 0x5780, 0x9741, 0x5500, 0x95c1, 0x9481, 0x5440,
	0x9c01, 0x5cc0, 0x5d80, 0x9d41, 0x5f00, 0x9fc1, 0x9e81, 0x5e40,
	0x5a00, 0x9ac1, 0x9b81, 0x5b40, 0x9901, 0x59c0, 0x5880, 0x9841,
	0x8801, 0x48c0, 0x4980, 0x8941, 0x4b00, 0x8bc1, 0x8a81, 0x4a40,
	0x4e00, 0x8ec1, 0x8f81, 0x4f40, 0x8d01, 0x4dc0, 0x4c80, 0x8c41,
	0x4400, 0x84c1, 0x8581, 0x4540, 0x8701, 0x47c0, 0x4680, 0x8641,
	0x8201, 0x42c0, 0x4380, 0x8341, 0x4100, 0x81c1, 0x8081, 0x4040
};


/*================================================================*/
/* Local Function Declarations */

void	usage(void);
int	read_srecfile(char *fname);
int	mkimage(imgchunk_t *clist, UINT *ccnt);
int	read_pdrfile( char *fname, int isnew);
int	read_cardpda(pda_t *pda, char *dev);
int	read_filepda(pda_t *pda, char *pdrfname);
void    merge_pda(pda_t *pda, UINT16 *pdwords, int nword);
int	mkpdrlist( pda_t *pda);
int	do_ioctl( p80211msg_t *msg );
void	print_all_pdrs(pda_t *pda);
int	str2macaddr( UINT8 *a, char *s );
int	s3datarec_compare(const void *p1, const void *p2);
int	mkpda_crc( pda_t *pda);
int	pda_write(pda_t *pda);
int	plugimage( imgchunk_t *fchunk, UINT nfchunks, 
		s3plugrec_t* s3plug, UINT ns3plug, pda_t *pda,
		char *fname);
int	crcimage( imgchunk_t *fchunk, UINT nfchunks, 
		s3crcrec_t *s3crc, UINT ns3crc);
int	writeimage(imgchunk_t *fchunk, UINT nfchunks, int isflash);
void	free_chunks(imgchunk_t *fchunk, UINT* nfchunks);
void	free_srecs(void);
void	dumpchunks( imgchunk_t *fchunk, UINT nfchunks);

int     validate_identity(void);

/*================================================================*/
/* Function Definitions */


/*----------------------------------------------------------------
* main
*
* prism2dl entry point.
*
* Arguments:
*	argc	number of command line arguments
*	argv	array of argument strings
*
* Returns: 
*	0	- success 
*	~0	- failure
----------------------------------------------------------------*/
int main ( int argc, char **argv )
{
	INT	result = 0;
	int	optch;
	int	i;
	int	pda_changed = 0;	/* has cardpda been altered? */

	strcpy( appname, APPNAME );
	fullname = argv[0];

	/* Initialize the data structures */
	memset(rfname, 0, sizeof(rfname));
	memset(ffname, 0, sizeof(ffname));
	memset(addpdrfname, 0, sizeof(addpdrfname));
	memset(newpdafname, 0, sizeof(newpdafname));
	memset(macaddr, 0, sizeof(macaddr));
	memset(sernum, 0, sizeof(sernum));
	memset(devname, 0, sizeof(devname));

	ns3data = 0;
	memset(s3data, 0, sizeof(s3data));
	ns3plug = 0;
	memset(s3plug, 0, sizeof(s3plug));
	ns3crc = 0;
	memset(s3crc, 0, sizeof(s3crc));
	ns3info = 0;
	memset(s3info, 0, sizeof(s3info));
	startaddr = 0;

	nfchunks = 0;
	memset( fchunk, sizeof(fchunk), 0);

	memset( &nicid, sizeof(nicid), 0);
	memset( &rfid, sizeof(rfid), 0);
	memset( &macid, sizeof(macid), 0);
	memset( &priid, sizeof(priid), 0);

	/* clear the pda and add an initial END record */
	memset(&pda, 0, sizeof(pda));
	pda.rec[0] = (hfa384x_pdrec_t*)pda.buf;
	pda.rec[0]->len = host2hfa384x_16(2);  	/* len in words */  			/* len in words */
	pda.rec[0]->code = host2hfa384x_16(HFA384x_PDR_END_OF_PDA);
	pda.nrec = 1;

	/* if no args, print the usage msg */
	if ( argc < 2 ) {
		usage();
		return -1;
	}

	/* collect the args */
	while ( ((optch = getopt(argc, argv, opts)) != EOF) && (result == 0) ) {
		switch (optch)
		{
		case 'v':
			/* Verbose operation */
			opt_verbose = 1;
			break;
		case 'V':
			/* Display version and exit */
			printf("%s utility version %s\n", appname, WLAN_RELEASE);
			return 0;
			break;
		case 'n':
			/* Process files and card PDA, no download */
			opt_nowrite = 1;
			break;
		case 'd':
			/* Process files, no card PDA, no download */
			opt_debug = 1;
			opt_verbose = 1;
			break;
		case 'D':
			/* dump chunks */
			opt_dumpchunks = 1;
			break;
		case 's':
			/* Show status */
			opt_status = 1;
			break;
		case 'g':
			/* File generate */
			opt_generate = 1;
			break;

		case 'r':
			/* Ram image filename, add to list */
			if ( opt_ramloadcnt >= RAMFILES_MAX ) {
				fprintf(stderr,APPNAME": too many RAM files on cmd line. Exiting.\n");
				exit(1);
			}
			strncpy(rfname[opt_ramloadcnt], optarg, FILENAME_MAX);
			opt_ramloadcnt++;
			break;
		case 'f':
			/* Flash image filename, add to list */
			if ( opt_flashloadcnt >= FLASHFILES_MAX ) {
				fprintf(stderr,APPNAME": too many FLASH files on cmd line. Exiting.\n");
				exit(1);
			}
			strncpy(ffname[opt_flashloadcnt], optarg, FILENAME_MAX);
			opt_flashloadcnt++;
			break;
		case 'a':
			/* Flash image filename, add to list */
			if ( opt_addpdrcnt >= ADDPDRFILES_MAX ) {
				fprintf(stderr,APPNAME": too many ADDPDR files on cmd line. Exiting.\n");
				exit(1);
			}
			strncpy(addpdrfname[opt_addpdrcnt], optarg, FILENAME_MAX);
			opt_addpdrcnt++;
			break;
		case 'p':
			/* New PDA filename */
			if ( opt_newpda ) {
				fprintf(stderr,APPNAME": -p specified more than once. Exiting.\n");
				exit(1);
			}
			opt_newpda = 1;
			strncpy(newpdafname, optarg, FILENAME_MAX);
			break;
		case 'l':
			opt_pdaloc = strtoul(optarg, NULL, 0);
			break;
		case 'm':
			/* cmdline MAC address */
			if ( opt_macaddr ) {
				fprintf(stderr,APPNAME": -m specified more than once. Exiting.\n");
				exit(1);
			}
			if ( str2macaddr(macaddr, optarg) != 0 ) {
				fprintf(stderr,APPNAME": mac address format error. Exiting.\n");
				exit(1);
			}
			opt_macaddr = 1;
			break;
		case 'S':
			/* cmdline Serial number */
			if ( opt_sernum ) {
				fprintf(stderr,APPNAME": -S specified more than once. Exiting.\n");
				exit(1);
			}
			strncpy( sernum, optarg, SERNUM_LEN_MAX);
			opt_sernum = 1;
			break;
		default:
			fprintf(stderr,APPNAME": unrecognized option -%c.\n", optch);
			usage();
			return -1;
			break;
		}
	}

	/* check for options that are mutually exclusive */
	if ( opt_debug && opt_nowrite ) {
		fprintf(stderr,APPNAME": -n and -d are mutually exclusive. Exiting.\n");
		exit(1);
	}

	/*-----------------------------------------------------*/
	/* if we made it this far, the options must be pretty much OK */
	/* save the interface name */
	if ( optind >= argc && !opt_debug ) {
		/* we're missing the interface argument */
		fprintf(stderr, APPNAME": missing argument - devname\n");
		usage();
		return -1;
	} else if (!opt_debug) {
		/* save the interface name */
		strncpy( devname, argv[optind], sizeof(devname) );
	}

	/*-----------------------------------------------------*/
	/* Build the PDA we're going to use. */
	pda_changed = 0;
	if ( !opt_newpda && !opt_debug ) { /* read pda from card */
		if (read_cardpda(&pda, devname)) {
			fprintf(stderr,"load_cardpda failed, exiting.\n");
			exit(1);
		}

		if ( opt_status && opt_addpdrcnt) { /* print note about pda */
			printf( "Card PDA prior to file generated "
				"modifications:\n");
		}
	} else if ( opt_newpda ){ /* read pda from file */
		pda_changed = 1;
		read_filepda(&pda, newpdafname);
		if  (opt_status && opt_addpdrcnt) {
			printf( "File PDA prior to file generated "
				"modifications:\n");
		}
	}

	/* read the card's PRI-SUP */
	if (!opt_debug) {
		p80211msg_dot11req_mibget_t getmsg;
		p80211itemd_t *item;
		UINT32        *data;

		memset(&getmsg, 0, sizeof(getmsg));
		getmsg.msgcode = DIDmsg_dot11req_mibget;
		getmsg.msglen = sizeof(getmsg);
		strcpy(getmsg.devname, devname);

		getmsg.mibattribute.did = DIDmsg_dot11req_mibget_mibattribute;
		getmsg.mibattribute.status = P80211ENUM_msgitem_status_data_ok;
		getmsg.resultcode.did = DIDmsg_dot11req_mibget_resultcode;
		getmsg.resultcode.status = P80211ENUM_msgitem_status_no_value;

		item = (p80211itemd_t *) getmsg.mibattribute.data;
		item->did = DIDmib_p2_p2NIC_p2PRISupRange;
		item->status = P80211ENUM_msgitem_status_no_value;
		
		data = (UINT32*) item->data;

		do_ioctl((p80211msg_t*)&getmsg);
		if (getmsg.resultcode.data != P80211ENUM_resultcode_success) {
			printf("Couldn't fetch PRI-SUP info\n");
		}

		/* Already in host order */
		priid.role = *data++;
		priid.id = *data++;
		priid.variant = *data++;
		priid.bottom = *data++;
		priid.top = *data++;
	}

	/* If the MAC address is specified it should overwrite the
         * current value. 
	 */
	if ( opt_macaddr ) {
		const unsigned nwords = WLAN_ADDR_LEN/sizeof(UINT16) + 2;
		UINT16 pdwords[nwords];
		int i; /* index into byte array of macaddr */
		int j; /* index into pdr words */

		/* create mac address PDR
		word[0] : PDR length
		word[1] : MAC address PDR code (0x101)
		word[2-4] : MAC address (WLAN_ADDR_LEN bytes - usually 6) 
		*/
		pdwords[0] = host2hfa384x_16(0x0004);
		pdwords[1] = host2hfa384x_16(0x0101);
		for (i = 0, j = 2; i < WLAN_ADDR_LEN; i += 2, j++) {
			pdwords[j] = host2hfa384x_16((UINT16) macaddr[i+1] << 8 | (UINT16) macaddr[i]);
		}
		/* merge the value into the PDA, so that it will eventually
		 * be written. 
		 */
		merge_pda(&pda, pdwords, nwords);
		pda_changed = 1;
	}

	/* If a serial number is specified add it to the PDA. */
	if ( opt_sernum ) {
		const unsigned nwords = SERNUM_LEN_MAX/sizeof(UINT16) + 2;
		UINT16 pdwords[nwords];
		int i; /* index into byte array of serial numbers bytes */
		int j; /* index into pdr words */

		/* create mac address PDR
		word[0] : PDR length
		word[1] : Serial number PDR code (0x0003)
		word[2-7] : Serial number (12 bytes)
		*/
		pdwords[0] = host2hfa384x_16(0x0007);
		pdwords[1] = host2hfa384x_16(0x0003);
		for (i = 0, j = 2; i < SERNUM_LEN_MAX; i += 2, j++) {
			pdwords[j] = host2hfa384x_16((UINT16) sernum[i+1] << 8 | (UINT16) sernum[i]);
		}
		/* merge the value into the PDA, so that it will eventually
		 * be written. 
		 */
		merge_pda(&pda, pdwords, nwords);
		pda_changed = 1;
	}
	  
	if ( opt_status || opt_generate ) { /* print pda */
		print_all_pdrs(&pda);
	}

	if ( opt_addpdrcnt ) { /* read the "add pdas" and merge them*/
		pda_changed = 1;
		for ( i = 0; i < opt_addpdrcnt; i++) {
			read_filepda(&pda, addpdrfname[i]);
		}
	}

	if ( pda_changed ) { /* calculate the CRC for the new PDA */
		mkpda_crc(&pda);
	}

	if ( (opt_status || opt_generate ) && pda_changed ) {
		printf("PDA after crc calc and/or \"-a\" file "
			"generated modifications:\n");
		print_all_pdrs(&pda);
		/* Read and print the CIS? */
		exit(0);
	} else if  ( opt_status || opt_generate ) { /* We're done */
		exit(0);  
	}

	if ( opt_ramloadcnt && !opt_flashloadcnt ) {
		if (pda_changed) {
		printf("Warning: RAM load only, PDA changes will NOT be written to flash.\n");
		}
		goto skip_pda_write;
	}

	if ( !opt_debug && !opt_nowrite && pda_changed) { /* write the PDA */
		if ( opt_pdaloc == 0 ) {
			fprintf(stderr, APPNAME ": error, you must specifify a pda location\n");
			usage();
			exit(1);
		}
		pda_write(&pda);
	}
skip_pda_write:

	/*-----------------------------------------------------*/
	/* Read the flash files */
	if ( opt_flashloadcnt ) {
		for ( i = 0; i < opt_flashloadcnt; i++) { /* For each file */
			/* Read the S3 file */
			result = read_srecfile(ffname[i]);
			if ( result ) {
				fprintf(stderr, APPNAME
					": Failed to read %s, exiting.\n",
					ffname[i]);
				exit(1);
			}
			/* Sort the S3 data records */
			qsort( s3data, 
				ns3data,
				sizeof(s3datarec_t),
				s3datarec_compare);

			result = validate_identity();

			if (startaddr != 0x00000000) {
				fprintf(stderr, APPNAME ": Can't flash a RAM download image!\n");
				exit(1);
			}

			if ( result ) {
				fprintf(stderr, APPNAME ": Incompatible firmware image.\n");
				exit(1);
			}

			/* Make the image chunks */
			result = mkimage(fchunk, &nfchunks);

			/* Do any plugging */
			result = plugimage(fchunk, nfchunks, s3plug, ns3plug, 
						&pda, ffname[i]);
			if ( result ) {
				fprintf(stderr, APPNAME
					": Failed to plug data for %s, exiting.\n",
					ffname[i]);
				exit(1);
			}

			/* Insert any CRCs */
			if (crcimage(fchunk, nfchunks, s3crc, ns3crc) ) {
				fprintf(stderr, APPNAME
					": Failed to insert all CRCs for "
					"%s, exiting.\n",
					ffname[i]);
				exit(1);
			}

			/* Write the image */
			if ( opt_nowrite ) continue;
			result = writeimage(fchunk, nfchunks, 1);
			if ( result ) {
				fprintf(stderr, APPNAME
					": Failed to flashwrite image data for "
					"%s, exiting.\n",
					ffname[i]);
				exit(1);
			}
			/* clear any allocated memory */
			free_chunks(fchunk, &nfchunks);
			free_srecs();
		}
	}

	/* Read the ram files */
	if ( opt_ramloadcnt ) {
		for ( i = 0; i < opt_ramloadcnt; i++) { /* For each file */
			/* Read the S3 file */
			result = read_srecfile(rfname[i]);
			if ( result ) {
				fprintf(stderr, APPNAME
					": Failed to read %s, exiting.\n",
					rfname[i]);
				exit(1);
			}
			/* Sort the S3 data records */
			qsort( s3data, 
				ns3data,
				sizeof(s3datarec_t),
				s3datarec_compare);

			result = validate_identity();

			if ( result && !opt_newpda ) {
				fprintf(stderr, APPNAME ": Incompatible firmware image.\n");
				exit(1);
			}

			if (startaddr == 0x00000000) {
				fprintf(stderr, APPNAME ": Can't RAM download a Flash image!\n");
				exit(1);
			}

			/* Make the image chunks */
			result = mkimage(fchunk, &nfchunks);

			/* Do any plugging */
			result = plugimage(fchunk, nfchunks, s3plug, ns3plug, 
						&pda, rfname[i]);
			if ( result ) {
				fprintf(stderr, APPNAME
					": Failed to plug data for %s, exiting.\n",
					rfname[i]);
				exit(1);
			}

			/* Insert any CRCs */
			if (crcimage(fchunk, nfchunks, s3crc, ns3crc) ) {
				fprintf(stderr, APPNAME
					": Failed to insert all CRCs for "
					"%s, exiting.\n",
					rfname[i]);
				exit(1);
			}

			if ( opt_dumpchunks ) {
				/* Dump the contents of the image chunks */
				dumpchunks(fchunk, nfchunks);
			}

			/* Write the image */
			if ( opt_nowrite ) continue;
			result = writeimage(fchunk, nfchunks, 0);
			if ( result ) {
				fprintf(stderr, APPNAME
					": Failed to ramwrite image data for "
					"%s, exiting.\n",
					rfname[i]);
				exit(1);
			}

			/* clear any allocated memory */
			free_chunks(fchunk, &nfchunks);
			free_srecs();
		}
	}

	printf(APPNAME": finished.\n");

	return result;
}


/*----------------------------------------------------------------
* crcimage
*
* Adds a CRC16 in the two bytes prior to each block identified by
* an S3 CRC record.  Currently, we don't actually do a CRC we just
* insert the value 0xC0DE in hfa384x order.  
*
* Arguments:
*	fchunk		Array of image chunks
*	nfchunks	Number of image chunks
*	s3crc		Array of crc records
*	ns3crc		Number of crc records
*
* Returns: 
*	0	success
*	~0	failure
----------------------------------------------------------------*/
int crcimage(imgchunk_t *fchunk, UINT nfchunks, s3crcrec_t *s3crc, UINT ns3crc)
{
	int	result = 0;
	int	i;
	int	c;
	UINT32	crcstart;
	UINT32	crcend;
	UINT32	cstart = 0;
	UINT32	cend;
	UINT8	*dest;
	UINT32	chunkoff;

	for ( i = 0; i < ns3crc; i++ ) {
		if ( !s3crc[i].dowrite ) continue;
		crcstart = s3crc[i].addr;
		crcend =   s3crc[i].addr + s3crc[i].len;
		/* Find chunk */
		for ( c = 0; c < nfchunks; c++) {
			cstart = fchunk[c].addr;
			cend =	 fchunk[c].addr + fchunk[c].len;
			/*  the line below does an address & len match search */
			/*  unfortunately, I've found that the len fields of */
			/*  some crc records don't match with the length of */
			/*  the actual data, so we're not checking right */
			/*  now */
			/* if ( crcstart-2 >= cstart && crcend <= cend ) break;*/

			/* note the -2 below, it's to make sure the chunk has */
			/*   space for the CRC value */
			if ( crcstart-2 >= cstart && crcstart < cend ) break;
		}
		if ( c >= nfchunks ) {
			fprintf(stderr, APPNAME
				": Failed to find chunk for "
				"crcrec[%d], addr=0x%06lx len=%ld , "
				"aborting crc.\n", 
				i, s3crc[i].addr, s3crc[i].len);
			return 1;
		}
		
		/* Insert crc */
		if (opt_verbose) {
			printf("Adding crc @ 0x%06lx\n", s3crc[i].addr-2);
		}
		chunkoff = crcstart - cstart - 2;
		dest = fchunk[c].data + chunkoff;
		*dest =     0xde;
		*(dest+1) = 0xc0;

	}
	return result;
}


/*----------------------------------------------------------------
* do_ioctl
*
* Performs the ioctl call to send a message down to an 802.11
* device.
*
* Arguments:
*	msg	the message to send
*
* Returns: 
*	0	success
*	~0	failure
----------------------------------------------------------------*/
int do_ioctl( p80211msg_t *msg )
{
	int			result = 0;
	int			fd;
	p80211ioctl_req_t	req;

	/* set the magic */
	req.magic = P80211_IOCTL_MAGIC;

	/* get a socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if ( fd == -1 ) {
		result = errno;
		perror(APPNAME);
	} else {
		req.len = msg->msglen;
		req.data = msg;
		strcpy( req.name, msg->devname);
		req.result = 0;

		result = ioctl( fd, P80211_IFREQ, &req);

		if ( result == -1 ) {
			result = errno;
			perror(APPNAME);
		}
		close(fd);
	}
	return result;
}


/*----------------------------------------------------------------
* free_chunks
*
* Clears the chunklist data structures in preparation for a new file.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
----------------------------------------------------------------*/
void free_chunks(imgchunk_t *fchunk, UINT* nfchunks)
{
	int i;
	for ( i = 0; i < *nfchunks; i++) {
		if ( fchunk[i].data != NULL ) {
			free(fchunk[i].data);
		}
	}
	*nfchunks = 0;
	memset( fchunk, sizeof(fchunk), 0);

}


/*----------------------------------------------------------------
* free_srecs
*
* Clears the srec data structures in preparation for a new file.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
----------------------------------------------------------------*/
void free_srecs(void)
{
	int i;
	for ( i = 0; i < ns3data; i++) {
		free(s3data[i].data);
	}
	ns3data = 0;
	memset(s3data, 0, sizeof(s3data));
	ns3plug = 0;
	memset(s3plug, 0, sizeof(s3plug));
	ns3crc = 0;
	memset(s3crc, 0, sizeof(s3crc));
	ns3info = 0;
	memset(s3info, 0, sizeof(s3info));
	startaddr = 0;
}


/*----------------------------------------------------------------
* mkimage
*
* Scans the currently loaded set of S records for data residing
* in contiguous memory regions.  Each contiguous region is then
* made into a 'chunk'.  This function assumes that we're building
* a new chunk list.  Assumes the s3data items are in sorted order.
*
* Arguments:	none
*
* Returns: 
*	0	- success 
*	~0	- failure (probably an errno)
----------------------------------------------------------------*/
int mkimage(imgchunk_t *clist, UINT *ccnt)
{
	int		result = 0;
	int		i;
	int		j;
	int		currchunk = 0;
	UINT32		nextaddr = 0;
	UINT32		s3start;
	UINT32		s3end;
	UINT32		cstart = 0;
	UINT32		cend;
	UINT32		coffset;
	
	/* There may already be data in the chunklist */
	*ccnt = 0;

	/* Establish the location and size of each chunk */
	for ( i = 0; i < ns3data; i++) {
		if ( s3data[i].addr == nextaddr ) { 
			/* existing chunk, grow it */
			clist[currchunk].len += s3data[i].len;
			nextaddr += s3data[i].len;
		} else {
			/* New chunk */
			(*ccnt)++;
			currchunk = *ccnt - 1;
			clist[currchunk].addr = s3data[i].addr;
			clist[currchunk].len = s3data[i].len;
			nextaddr = s3data[i].addr + s3data[i].len;
			/* Expand the chunk if there is a CRC record at */
			/* their beginning bound */
			for ( j = 0; j < ns3crc; j++) {
				if ( s3crc[j].dowrite &&
				     s3crc[j].addr == clist[currchunk].addr ) {
					clist[currchunk].addr -= 2;
					clist[currchunk].len += 2;
				}
			}
		}
	}

	/* We're currently assuming there aren't any overlapping chunks */
	/*  if this proves false, we'll need to add code to coalesce. */

	/* Allocate buffer space for chunks */
	for ( i = 0; i < *ccnt; i++) {
		clist[i].data = malloc(clist[i].len);
		if  ( clist[i].data == NULL ) {
			fprintf(stderr, APPNAME": failed to allocate image space, exitting.\n");
			exit(1);
		}
		memset(clist[i].data, 0, clist[i].len);
	}


	/* Display chunks */
	if ( opt_verbose ) {
		for ( i = 0; i < *ccnt;  i++) {
			printf("chunk[%d]: addr=0x%06lx len=%ld\n", 
				i, clist[i].addr, clist[i].len);
		}
	}

	/* Copy srec data to chunks */
	for ( i = 0; i < ns3data; i++) {
		s3start = s3data[i].addr;
		s3end   = s3start + s3data[i].len - 1;
		for ( j = 0; j < *ccnt; j++) {
			cstart = clist[j].addr;
			cend = cstart + clist[j].len - 1;
			if ( s3start >= cstart && s3end <= cend ) {
				break;
			}
		}
		if ( ((UINT)j) >= (*ccnt) ) {
			fprintf(stderr,APPNAME
			":s3rec(a=0x%06lx,l=%ld), no chunk match, exiting.\n",
			s3start, s3data[i].len);
			exit(1);
		}
		coffset = s3start - cstart;
		memcpy( clist[j].data + coffset, s3data[i].data, s3data[i].len);
	}

	return result;
}


/*----------------------------------------------------------------
* mkpda_crc
*
* Calculates the CRC16 for the given PDA and inserts the value
* into the end record.
*
* Arguments:
*	pda	ptr to the PDA data structure.
*
* Returns: 
*	0	- success 
*	~0	- failure (probably an errno)
----------------------------------------------------------------*/
int mkpda_crc( pda_t *pda)
{
	int	result = 0;
	UINT8	*p;
	UINT8	*lim;
	UINT16	crc = 0;

	p = pda->buf;
	/* pda->nrec-1 _better_ be the end record */
	/* get ptr to last rec */
	lim = (UINT8*)(pda->rec[pda->nrec - 1]);
	lim += sizeof(UINT16) * 2;   /* increase to include len&code fields */
	while (p < lim) {	
		crc = (crc >> 8 ) ^ crc16tab[(crc & 0xff) ^ *p++];
	}

	/* assign to endrec field */
	pda->rec[pda->nrec - 1]->data.end_of_pda.crc = host2hfa384x_16(crc);

	if (opt_debug) {
		printf("%s: pdacrc=0x%04x\n", __FUNCTION__, crc);
	}

	return result;
}


/*----------------------------------------------------------------
* mkpdrlist
*
* Reads a raw PDA and builds an array of pdrec_t structures.
*
* Arguments:
*	pda	buffer containing raw PDA bytes
*	pdrec	ptr to an array of pdrec_t's.  Will be filled on exit.
*	nrec	ptr to a variable that will contain the count of PDRs
*
* Returns: 
*	0	- success 
*	~0	- failure (probably an errno)
----------------------------------------------------------------*/
int mkpdrlist( pda_t *pda)
{
	int	result = 0;
	UINT16	*pda16 = (UINT16*)pda->buf;
	int	curroff;	/* in 'words' */

	pda->nrec = 0;
	curroff = 0;
	while ( curroff < (HFA384x_PDA_LEN_MAX / 2) &&
		hfa384x2host_16(pda16[curroff + 1]) !=
		HFA384x_PDR_END_OF_PDA ) {
		pda->rec[pda->nrec] = (hfa384x_pdrec_t*)&(pda16[curroff]);

		if (hfa384x2host_16(pda->rec[pda->nrec]->code) ==
				HFA384x_PDR_NICID) {
			memcpy(&nicid, &pda->rec[pda->nrec]->data.nicid,
			       sizeof(nicid));
			nicid.id = hfa384x2host_16(nicid.id);
			nicid.variant = hfa384x2host_16(nicid.variant);
			nicid.major = hfa384x2host_16(nicid.major);
			nicid.minor = hfa384x2host_16(nicid.minor);
		}
		if (hfa384x2host_16(pda->rec[pda->nrec]->code) ==
				HFA384x_PDR_MFISUPRANGE) {
			memcpy(&rfid, &pda->rec[pda->nrec]->data.mfisuprange,
			       sizeof(rfid));
			rfid.id = hfa384x2host_16(rfid.id);
			rfid.variant = hfa384x2host_16(rfid.variant);
			rfid.bottom = hfa384x2host_16(rfid.bottom);
			rfid.top = hfa384x2host_16(rfid.top);
		}
		if (hfa384x2host_16(pda->rec[pda->nrec]->code) ==
				HFA384x_PDR_CFISUPRANGE) {
			memcpy(&macid, &pda->rec[pda->nrec]->data.cfisuprange,
			       sizeof(macid));
			macid.id = hfa384x2host_16(macid.id);
			macid.variant = hfa384x2host_16(macid.variant);
			macid.bottom = hfa384x2host_16(macid.bottom);
			macid.top = hfa384x2host_16(macid.top);
		}

		(pda->nrec)++;
		curroff += hfa384x2host_16(pda16[curroff]) + 1;

	}
	if ( curroff >= (HFA384x_PDA_LEN_MAX / 2) ) {
		fprintf(stderr, APPNAME
			": no end record found or invalid lengths in "
			"PDR data, exiting. %x %d\n", curroff, pda->nrec);
		exit(1);
	}
	if (hfa384x2host_16(pda16[curroff + 1]) == HFA384x_PDR_END_OF_PDA ) {
		pda->rec[pda->nrec] = (hfa384x_pdrec_t*)&(pda16[curroff]);
		(pda->nrec)++;
	}
	return result;
}


/*----------------------------------------------------------------
* pda_write
*
* Builds a message containing the PDA in the given pda structure
* and sends it to the device driver.  The driver will (hopefully)
* write the pda to the card flash.
*
* Arguments:
*	pda	structure containing the PDA we wish to write to
*		the card.
*
* Returns: 
*	0	success
*	~0	failure
----------------------------------------------------------------*/
int pda_write(pda_t *pda)
{
	int					result = 0;
	p80211msg_p2req_flashdl_state_t		statemsg;
	p80211msg_p2req_flashdl_write_t		writemsg;

	/* Initialize the messages */
	memset(&statemsg, 0, sizeof(statemsg));
	strcpy(statemsg.devname, devname);
	statemsg.msgcode =		DIDmsg_p2req_flashdl_state;
	statemsg.msglen =		sizeof(statemsg);
	statemsg.enable.did =		DIDmsg_p2req_flashdl_state_enable;
	statemsg.resultcode.did =	DIDmsg_p2req_flashdl_state_resultcode;
	statemsg.enable.status =	P80211ENUM_msgitem_status_data_ok;
	statemsg.resultcode.status =	P80211ENUM_msgitem_status_no_value;
	statemsg.enable.len =		sizeof(UINT32);
	statemsg.resultcode.len =	sizeof(UINT32);

	memset(&writemsg, 0, sizeof(writemsg));
	strcpy(writemsg.devname, devname);
	writemsg.msgcode =		DIDmsg_p2req_flashdl_write;
	writemsg.msglen =		sizeof(writemsg);
	writemsg.addr.did =		DIDmsg_p2req_flashdl_write_addr;
	writemsg.len.did =		DIDmsg_p2req_flashdl_write_len;
	writemsg.data.did =		DIDmsg_p2req_flashdl_write_data;
	writemsg.resultcode.did =	DIDmsg_p2req_flashdl_write_resultcode;
	writemsg.addr.status =		P80211ENUM_msgitem_status_data_ok;
	writemsg.len.status =		P80211ENUM_msgitem_status_data_ok;
	writemsg.data.status =		P80211ENUM_msgitem_status_data_ok;
	writemsg.resultcode.status =	P80211ENUM_msgitem_status_no_value;
	writemsg.addr.len =		sizeof(UINT32);
	writemsg.len.len =		sizeof(UINT32);
	writemsg.data.len =		WRITESIZE_MAX;
	writemsg.resultcode.len =	sizeof(UINT32);

	/* Send flashdl_state(enable) */
	if (opt_verbose) printf("Sending dlflash_state(enable) message.\n");
	statemsg.enable.data = P80211ENUM_truth_true;
	if ( !opt_debug ) {
		result = do_ioctl((p80211msg_t*)&statemsg);
		if ( result ) {
			fprintf(stderr,APPNAME
				": pda_write()->do_ioctl() failed w/ result=%d, "
				"aborting pda download\n", result);
			return result;
		}
		if ( statemsg.resultcode.data != P80211ENUM_resultcode_success ) {
			fprintf(stderr,APPNAME
				": pda_write()->flashdl_state msg indicates failure, "
				"w/ resultcode=%ld, aborting pda download.\n",
				statemsg.resultcode.data);
			return 1;
		}
	}

	/* Send flashdl_write(pda) */
	writemsg.addr.data = opt_pdaloc;
	writemsg.len.data = (((UINT8*)(pda->rec[pda->nrec - 1])) - pda->buf + 6);
	memcpy(writemsg.data.data, pda->buf, writemsg.len.data);
	if (opt_verbose) {
		printf("Sending dlflash_write, addr=%06lx len=%ld \n",
			writemsg.addr.data, writemsg.len.data);
	}
	if ( !opt_debug ) {
		result = do_ioctl((p80211msg_t*)&writemsg);
		if ( result ) {
			fprintf(stderr,APPNAME
				": pda_write()->do_ioctl() failed w/ result=%d, "
				"aborting pda download\n", result);
			return result;
		}
		if ( writemsg.resultcode.data != P80211ENUM_resultcode_success ) {
			fprintf(stderr,APPNAME
				": pda_write()->flashdl_write msg indicates failure, "
				"w/ resultcode=%ld, aborting pda download.\n",
				writemsg.resultcode.data);
			return 1;
		}
	}

	/* Send flashdl_state(disable) */
	if (opt_verbose) printf("Sending dlflash_state(disable) message.\n");
	statemsg.enable.data = P80211ENUM_truth_false;
	if ( !opt_debug ) {
		result = do_ioctl((p80211msg_t*)&statemsg);
		if ( result ) {
			fprintf(stderr,APPNAME
				": pda_write()->do_ioctl() failed w/ result=%d, "
				"aborting pda download\n", result);
			return result;
		}
		if ( statemsg.resultcode.data != P80211ENUM_resultcode_success ) {
			fprintf(stderr,APPNAME
				": pda_write()->flashdl_state msg indicates failure, "
				"w/ resultcode=%ld, aborting pda download.\n",
				statemsg.resultcode.data);
			return 1;
		}
	}
	return result;
}


/*----------------------------------------------------------------
* plugimage
*
* Plugs the given image using the given plug records from the given 
* PDA and filename.
*
* Arguments:
*	fchunk		Array of image chunks
*	nfchunks	Number of image chunks
*	s3plug		Array of plug records
*	ns3plug		Number of plug records
*	pda		Current pda data
*	fname		File the image data was read from
*
* Returns: 
*	0	success
*	~0	failure
----------------------------------------------------------------*/
int plugimage( imgchunk_t *fchunk, UINT nfchunks, 
		s3plugrec_t* s3plug, UINT ns3plug, pda_t *pda,
		char *fname)
{
	int	result = 0;
	int	i;	/* plug index */
	int	j;	/* index of PDR or -1 if fname plug */
	int	c;	/* chunk index */
	UINT32	pstart;
	UINT32	pend;
	UINT32	cstart = 0;
	UINT32	cend;
	UINT32	chunkoff;
	UINT8	*src;
	UINT8	*dest;

	/* for each plug record */
	for ( i = 0; i < ns3plug; i++) {
		pstart = s3plug[i].addr;
		pend = 	 s3plug[i].addr + s3plug[i].len;
		/* find the matching PDR (or filename) */
		if ( s3plug[i].itemcode != 0xffffffffUL ) { /* not filename */
			for ( j = 0; j < pda->nrec; j++) {
				if ( s3plug[i].itemcode == 
				     hfa384x2host_16(pda->rec[j]->code) ) break;
			}
		} else {
			j = -1;
		}
		if ( j >= pda->nrec && j != -1 ) { /*  if no matching PDR, fail */
			fprintf(stderr, APPNAME
				": warning: Failed to find PDR for "
				"plugrec 0x%04lx.\n",
				s3plug[i].itemcode);
			continue; /* and move on to the next PDR */

#if 0
			/* MSM: They swear that unless it's the MAC address,
			 * the serial number, or the TX calibration records,
			 * then there's reasonable defaults in the f/w
			 * image.  Therefore, missing PDRs in the card
			 * should only be a warning, not fatal.
			 * TODO: add fatals for the PDRs mentioned above.
			 */
			result = 1;
			continue; 
#endif
		}

		/* Validate plug len against PDR len */
		if ( j != -1 && 
		     s3plug[i].len < hfa384x2host_16(pda->rec[j]->len) ) {
			fprintf(stderr, APPNAME
				": error: Plug vs. PDR len mismatch for "
				"plugrec 0x%04lx, abort plugging.\n",
				s3plug[i].itemcode);
			result = 1;
			continue;
		}

		/* Validate plug address against chunk data and identify chunk */
		for ( c = 0; c < nfchunks; c++) {
			cstart = fchunk[c].addr;
			cend =	 fchunk[c].addr + fchunk[c].len;
			if ( pstart >= cstart && pend <= cend ) break;
		}
		if ( c >= nfchunks ) {
			fprintf(stderr, APPNAME
				": error: Failed to find image chunk for "
				"plugrec 0x%04lx.\n",
				s3plug[i].itemcode);
			result = 1;
			continue;
		}

		/* Plug data */
		chunkoff = pstart - cstart;
		dest = fchunk[c].data + chunkoff;
		if (opt_verbose) {
			printf("Plugging item 0x%04lx @ 0x%06lx, len=%ld, "
			       "cnum=%d coff=0x%06lx\n", 
				s3plug[i].itemcode, pstart, s3plug[i].len,
				c, chunkoff);
		}
		if ( j == -1 ) { /* plug the filename */
			src = strrchr(fname, '/');
			src = (src == NULL) ? (UINT8*)fname : src + 1;
			memset(dest, 0, s3plug[i].len);
			strncpy(dest, src, s3plug[i].len - 1);
		} else { /* plug a PDR */
			memcpy( dest, &(pda->rec[j]->data), s3plug[i].len);
		}
	}
	return result;

}

/*----------------------------------------------------------------
* print_all_pdrs
*
* Dumps the contents of all the pdr lists to stdout.  Assumes that
* the pdrlists have 'been made'.  See mkpdrlist().
*
* Arguments:	none
*
* Returns: 
*	0	- success 
*	~0	- failure (probably an errno)
----------------------------------------------------------------*/
void print_all_pdrs(pda_t *pda)
{
	int	i;
	int	j;
	UINT16	*datap;
	UINT8	*offp;
	int	end;
	int	nwords;

	if ( opt_generate ) {
		for ( i = 0; i < pda->nrec; i++) {
			datap = (UINT16*)(pda->rec[i]);
			nwords = hfa384x2host_16(pda->rec[i]->len) +1;
			for ( j = 0; j < nwords; j++) {
				printf("0x%04x, ", hfa384x2host_16(datap[j]));
			}
			printf("\n");
		}
		return;
	}

	printf("Current PDA:\n");
	printf( "   offset   len   code   data\n"
		"  ---------------------------------------------------\n");
	/*         00000000  000  0x0000  0000 0000 0000 0000 0000.... */
	/*                                0000 0000 0000 0000 0000.... */
	for ( i = 0; i < pda->nrec; i++) {
		offp = (UINT8*)(pda->rec[i]);
		printf("  %08d  %03d  0x%04x  ", 
			offp - pda->buf,
			hfa384x2host_16(pda->rec[i]->len),
			hfa384x2host_16(pda->rec[i]->code));
		datap = (UINT16*)&(pda->rec[i]->data.end_of_pda);
		nwords = hfa384x2host_16(pda->rec[i]->len) - 1;
		for ( j = 0; j < nwords; j++) {
			printf("%04x ", hfa384x2host_16(datap[j]) );
			if ( (j % 8) == 7 && j < nwords - 1 ) {
				printf("\n                         ");
			}
		}
		printf("\n");
	}

	if (opt_verbose) {
		printf("Raw PDA:\n");
		datap = (UINT16*)pda->buf;
		end = (((UINT8*)pda->rec[pda->nrec - 1]) - pda->buf + 6) / 2;
		printf("  ");
		for ( i = 0; i < end; i++ ) {
			printf("%04x ", hfa384x2host_16(datap[i]) );
			if ( (i % 16) == 15 ) {
				printf("\n  ");
			}
		}
		printf("\n");
	}
}


/*----------------------------------------------------------------
* read_cardpda
*
* Sends the command for the driver to read the pda from the card
* named in the device variable.  Upon success, the card pda is 
* stored in the "cardpda" variables.  Note that the pda structure
* is considered 'well formed' after this function.  That means
* that the nrecs is valid, the rec array has been set up, and there's
* a valid PDAEND record in the raw PDA data.
*
* Arguments:	none
*
* Returns: 
*	0	- success 
*	~0	- failure (probably an errno)
----------------------------------------------------------------*/
int read_cardpda(pda_t *pda, char *dev)
{
	int				result = 0;
	p80211msg_p2req_readpda_t	msg;

	/* set up the msg */
	msg.msgcode = DIDmsg_p2req_readpda;
	msg.msglen = sizeof(msg);
	strcpy(msg.devname, dev); 
	msg.pda.did = DIDmsg_p2req_readpda_pda;
	msg.pda.len = HFA384x_PDA_LEN_MAX;
	msg.pda.status = P80211ENUM_msgitem_status_no_value;
	msg.resultcode.did = DIDmsg_p2req_readpda_resultcode;
	msg.resultcode.len = sizeof(UINT32);
	msg.resultcode.status = P80211ENUM_msgitem_status_no_value;

	if ( do_ioctl((p80211msg_t*)&msg) != 0 ) {
		/* do_ioctl prints an errno if appropriate */
		result = -1;
	} else if ( msg.resultcode.data == P80211ENUM_resultcode_success ) {
		memcpy(pda->buf, msg.pda.data, HFA384x_PDA_LEN_MAX);
		result = mkpdrlist(pda);
	} else {
		/* resultcode must've been something other than success */
		result = -1;
	}

	return result;
}

/*---------------------------------------------------------------
* merge_pda

* Merge the given pdr records into the given pda.
* New PDR's are added.
* If a PDR already exists then the current PDR overwrites the existing one.
* If the PDR has a length of 1 then it is removed from the PDA.
---------------------------------------------------------------*/

void
merge_pda(pda_t *pda, UINT16 *pdword, int nwords)
{
	int		i = 0;
	int		j = 0;
	UINT8		*delpdastart;
	UINT8		*mvpdastart;
	UINT16		pdrlen;
	UINT16		pdrcode;
	UINT		mvlen;

	/* Now, merge into the pda */
	/* note that all the words are in hfa384x order */
	i = 0;
	while ( i < nwords ) { /* For each PDR in the new list */
		pdrlen  = hfa384x2host_16(pdword[i]);  /* in words */
		pdrcode = hfa384x2host_16(pdword[i+1]);

		if ( pdrlen > (HFA384x_PDR_LEN_MAX / 2) ) {
			fprintf(stderr,APPNAME": invalid pdr length (0x%04x) encountered (pdrcode=0x%04x), exiting.\n", pdrlen, pdrcode);
			exit(1);
		}

		for ( j = 0; j < pda->nrec; j++) { /* Find matching code in PDA */
			if ( pdrcode == hfa384x2host_16(pda->rec[j]->code) ) {
				break;
			}
		}

		if ( pdrlen == 1 && j < pda->nrec ) { /* Remove the pdr from the PDA */
			if (opt_verbose) {
				printf("  Removing PDR: code=%04x, len=%d\n", 
					pdrcode, pdrlen);
			}
			delpdastart = (UINT8*)(pda->rec[j]);
			mvpdastart = delpdastart + 
				((hfa384x2host_16(pda->rec[j]->len) + 1) * 
				sizeof(UINT16));
			mvlen = HFA384x_PDA_LEN_MAX - (mvpdastart - pda->buf);
			memmove( delpdastart, mvpdastart, mvlen);
			pda->nrec = 0;
			mkpdrlist(pda);
		} else if ( j < pda->nrec ) { /* Replace the pdr in the PDA */
			if (opt_verbose) {
				printf("  Replacing PDR: code=%04x, len=%d\n", 
					pdrcode, pdrlen);
			}
			if ( pdrlen == hfa384x2host_16(pda->rec[j]->len) ) { 
				/* just overwrite */
				memcpy( pda->rec[j], 
					&(pdword[i]), 
					(pdrlen + 1)*sizeof(UINT16));
			} else {
				fprintf( stderr, APPNAME
				": Replacing pdrs where (newlen!=oldlen) not "
				"supported.\n");
				exit(1);
			}
		} else { /* Add the pdr to the PDA */
			UINT8	*endp = (UINT8*)(pda->rec[pda->nrec - 1]);
			if (opt_verbose) {
				printf("  Adding PDR: code=%04x, len=%d\n", 
					pdrcode, pdrlen);
			}
			/* overwrite the existing end record and add a new one */
			memcpy( endp, &(pdword[i]), (pdrlen + 1)*sizeof(UINT16));
			pda->rec[pda->nrec] = (hfa384x_pdrec_t*)
				(endp +
				((pdrlen+1) * sizeof(UINT16)));
			pda->rec[pda->nrec]->len = host2hfa384x_16(2);
			pda->rec[pda->nrec]->code = host2hfa384x_16(HFA384x_PDR_END_OF_PDA);
			pda->rec[pda->nrec]->data.end_of_pda.crc = 0;
			pda->nrec++;
		}
		i += pdrlen + 1;
	}
}

/*----------------------------------------------------------------
* read_filepda
*
* Reads a collection of PDRs from a file and merges them into the
* current PDA data set maintained within this program.  The 
* PDA data set may be empty or not.
*
* ASSUMED FILE FORMAT:
* 	pdrline := <sep><hexnum><pdrline>[<sep>]
*	hexnum  := [0x][[:hexdigit:]]{1-4}
*	sep     := [,[:space:]][[:space:]]*
* COMMENTS:
*	ANY DETECTED CHARACTER that doesn't match 
*  	[[:space:][:hexdigit:],x] indicates the start of a comment
*  	that extends to EOL.  Note the 'x',  it never starts an element
*  	so we really don't have to worry about it.
* REMOVE RECORDS:
*	PDR items in the file that have a length of 1 indicate that
*	the given PDR should be removed from the PDA.  If that
*	same item appears later in the file (or in a subsequent
*	file) then it will be added again.
*
* Arguments:	none
*
* Returns: 
*	0	- success 
*	~0	- failure (probably an errno)
----------------------------------------------------------------*/
int read_filepda(pda_t *pda, char *pdrfname)
{
	int		result = 0;
	FILE		*pdrfile;
	UINT16		pdword[HFA384x_PDA_LEN_MAX / sizeof(UINT16)];
	UINT		nwords = 0;
	char		linebuf[PDAFILE_LINE_MAX];
	char		*currp = NULL;
	char		*nextp = NULL;
	regex_t		regex;
	regmatch_t	regmatch;
	char		ebuf[100];

	/* Open the file */
	pdrfile = fopen(pdrfname, "r");
	if ( pdrfile == NULL ) {
		result=errno;
		perror(APPNAME);
		return result;
	}
	printf("Processing PDR file: %s\n", pdrfname);

	/* Read all the words, skipping over the comments etc. */
	memset(linebuf, 0,  PDAFILE_LINE_MAX);
	result = regcomp( &regex, "[,[:blank:]][[:blank:]]*", 0);
	if ( result != 0 ) {
		regerror( result, &regex, ebuf, sizeof(ebuf));
		fprintf(stderr, APPNAME": failed to compile pda regexp err=%s.\n", ebuf);
		exit(1);
	}
	while ( fgets(linebuf, PDAFILE_LINE_MAX, pdrfile) != NULL) {
		currp = linebuf;
		nextp = NULL;
		pdword[nwords] = strtoul( currp, &nextp, 16);
		if ( currp == nextp ) { /* is there noting valid? */
			continue;
		} else {
			pdword[nwords] = host2hfa384x_16(pdword[nwords]);
			nwords++;
			currp = nextp;
		}
		while ( regexec(&regex, currp, 1, &regmatch, 0) == 0 ) {
			currp += regmatch.rm_eo;
			if ( !isxdigit(*currp) ) {
				/* Assume comment and move to next line */
				memset(linebuf, 0,  PDAFILE_LINE_MAX);
				break;
			}
			pdword[nwords] = strtoul( currp, &nextp, 16);
			pdword[nwords] = host2hfa384x_16(pdword[nwords]);
			/* printf("pdword=%04x currp=\"%s\"\n", pdword[nwords], currp); */
			nwords++;
			currp = nextp;
		}
		memset(linebuf, 0,  PDAFILE_LINE_MAX);
	}

	/* Merge the records into the pda */
	merge_pda(pda, pdword, nwords);

	return result;
}


/*----------------------------------------------------------------
* read_srecfile
*
* Reads the given srecord file and loads the records into the 
* s3xxx arrays.  This function can be called repeatedly (once for
* each of a set of files), if necessary.  This function performs
* no validation of the data except for the grossest of S-record
* line format checks.  Don't forget that these will be DOS files...
* CR/LF at the end of each line.
*
* Here's the SREC format we're dealing with:
* S[37]nnaaaaaaaaddd...dddcc
*
*       nn - number of bytes starting with the address field
* aaaaaaaa - address in readable (or big endian) format
* dd....dd - 0-245 data bytes (two chars per byte)
*       cc - checksum
*
* The S7 record's (there should be only one) address value gets
* saved in startaddr.  It's the start execution address used
* for RAM downloads. 
*
* The S3 records have a collection of subformats indicated by the
* value of aaaaaaaa:
*   0xff000000 - Plug record, data field format:
*                xxxxxxxxaaaaaaaassssssss
*                x - PDR code number (little endian)
*                a - Address in load image to plug (little endian)
*                s - Length of plug data area (little endian)
*
*   0xff100000 - CRC16 generation record, data field format:
*                aaaaaaaassssssssbbbbbbbb
*                a - Start address for CRC calculation (little endian)
*                s - Length of data to  calculate over (little endian)
*                b - Boolean, true=write crc, false=don't write
*   
*   0xff200000 - Info record, data field format:
*                ssssttttdd..dd
*                s - Size in words (little endian)
*                t - Info type (little endian), see #defines and 
*                    s3inforec_t for details about types.
*                d - (s - 1) little endian words giving the contents of
*                    the given info type.
*
* Arguments:
*	fname	name of the s-record file to load
*
* Returns: 
*	0	- success 
*	~0	- failure (probably an errno)
----------------------------------------------------------------*/
int read_srecfile(char *fname)
{
	FILE*		f;
	int		result = 0;
	char		buf[SREC_LINE_MAX];
	char		tmpbuf[30];
	s3datarec_t	tmprec;
	int		i;
	int		line = 0;
	UINT16		*tmpinfo;
	

	printf("Reading S-record file %s...\n", fname);
	if ( strcmp("stdin", fname) == 0 ) {
		f = stdin;
	} else {
		f = fopen(fname, "r");
		if ( f == NULL ) {
			result=errno;
			perror(APPNAME);
			return result;
		}
	}

	while ( fgets(buf, sizeof(buf), f) != NULL ) {
		line++;
		if ( buf[0] != 'S' ) {
			fprintf(stderr,APPNAME":%s:%d warning: No initial \'S\'\n", fname, line);
			fclose(f);
			return 1;
		}
		if ( buf[1] == '7' ) {	/* S7 record, start address */
			buf[12] = '\0';
			startaddr = strtoul(buf+4, NULL, 16);
			if (opt_verbose) {
				printf( "  S7 start addr, line=%d "
					" addr=0x%08lx\n", 
					line, 
					startaddr);
			}
//			break;
			continue;
		} else if ( buf[1] != '3') {
			fprintf(stderr,APPNAME":%s:%d warning: Unknown S-record detected.\n", fname, line);
			fclose(f);
			return 1;
		}
		/* Ok, it's an S3, parse and put it in the right array */
		/* Record Length field (we only want datalen) */
		memcpy(tmpbuf, buf+S3LEN_TXTOFFSET, S3LEN_TXTLEN);
		tmpbuf[S3LEN_TXTLEN] = '\0';
		tmprec.len = strtoul( tmpbuf, NULL, 16) - 4 - 1; /* 4=addr, 1=cksum */
		/* Address field */
		memcpy(tmpbuf, buf+S3ADDR_TXTOFFSET, S3ADDR_TXTLEN);
		tmpbuf[S3ADDR_TXTLEN] = '\0';
		tmprec.addr = strtoul( tmpbuf, NULL, 16);
		/* Checksum field */
		tmprec.checksum = strtoul( buf+strlen(buf)-2, NULL, 16);

		switch(  tmprec.addr )
		{
		case S3ADDR_PLUG:
			memcpy(tmpbuf, buf+S3PLUG_ITEMCODE_TXTOFFSET, S3PLUG_ITEMCODE_TXTLEN);
			tmpbuf[S3PLUG_ITEMCODE_TXTLEN] = '\0';
			s3plug[ns3plug].itemcode = strtoul(tmpbuf,NULL,16);
			s3plug[ns3plug].itemcode = bswap_32(s3plug[ns3plug].itemcode);

			memcpy(tmpbuf, buf+S3PLUG_ADDR_TXTOFFSET, S3PLUG_ADDR_TXTLEN);
			tmpbuf[S3PLUG_ADDR_TXTLEN] = '\0';
			s3plug[ns3plug].addr = strtoul(tmpbuf,NULL,16);
			s3plug[ns3plug].addr = bswap_32(s3plug[ns3plug].addr);

			memcpy(tmpbuf, buf+S3PLUG_LEN_TXTOFFSET, S3PLUG_LEN_TXTLEN);
			tmpbuf[S3PLUG_LEN_TXTLEN] = '\0';
			s3plug[ns3plug].len = strtoul(tmpbuf,NULL,16);
			s3plug[ns3plug].len = bswap_32(s3plug[ns3plug].len);

			if (opt_verbose) {
				printf( "  S3 plugrec, line=%d "
					"itemcode=0x%04lx addr=0x%08lx len=%ld\n", 
					line, 
					s3plug[ns3plug].itemcode,
					s3plug[ns3plug].addr,
					s3plug[ns3plug].len);
			}

			ns3plug++;
			break;
		case S3ADDR_CRC:
			memcpy(tmpbuf, buf+S3CRC_ADDR_TXTOFFSET, S3CRC_ADDR_TXTLEN);
			tmpbuf[S3CRC_ADDR_TXTLEN] = '\0';
			s3crc[ns3crc].addr = strtoul(tmpbuf,NULL,16);
			s3crc[ns3crc].addr = bswap_32(s3crc[ns3crc].addr);

			memcpy(tmpbuf, buf+S3CRC_LEN_TXTOFFSET, S3CRC_LEN_TXTLEN);
			tmpbuf[S3CRC_LEN_TXTLEN] = '\0';
			s3crc[ns3crc].len = strtoul(tmpbuf,NULL,16);
			s3crc[ns3crc].len = bswap_32(s3crc[ns3crc].len);

			memcpy(tmpbuf, buf+S3CRC_DOWRITE_TXTOFFSET, S3CRC_DOWRITE_TXTLEN);
			tmpbuf[S3CRC_DOWRITE_TXTLEN] = '\0';
			s3crc[ns3crc].dowrite = strtoul(tmpbuf,NULL,16);
			s3crc[ns3crc].dowrite = bswap_32(s3crc[ns3crc].dowrite);

			if (opt_verbose) {
				printf( "  S3 crcrec, line=%d "
					"addr=0x%08lx len=%ld write=0x%08x\n", 
					line, 
					s3crc[ns3crc].addr,
					s3crc[ns3crc].len,
					s3crc[ns3crc].dowrite);
			}
			ns3crc++;
			break;
		case S3ADDR_INFO:
			memcpy(tmpbuf, buf+S3INFO_LEN_TXTOFFSET, S3INFO_LEN_TXTLEN);
			tmpbuf[S3INFO_LEN_TXTLEN] = '\0';
			s3info[ns3info].len = strtoul(tmpbuf,NULL,16);
			s3info[ns3info].len = bswap_16(s3info[ns3info].len);

			memcpy(tmpbuf, buf+S3INFO_TYPE_TXTOFFSET, S3INFO_TYPE_TXTLEN);
			tmpbuf[S3INFO_TYPE_TXTLEN] = '\0';
			s3info[ns3info].type = strtoul(tmpbuf,NULL,16);
			s3info[ns3info].type = bswap_16(s3info[ns3info].type);

			tmpinfo = (UINT16*)&(s3info[ns3info].info.version);
			for (i = 0; i < s3info[ns3info].len - 1; i++) {
				memcpy( tmpbuf, buf+S3INFO_DATA_TXTOFFSET+(i*4), 4);
				tmpbuf[4] = '\0';
				tmpinfo[i] = strtoul(tmpbuf,NULL,16);
				tmpinfo[i] = bswap_16(tmpinfo[i]);
			}
			if (opt_verbose) {
				printf( "  S3 inforec, line=%d "
					"len=0x%04x type=0x%04x\n", 
					line, 
					s3info[ns3info].len,
					s3info[ns3info].type);
				printf( "            info=");
				for (i = 0; i < s3info[ns3info].len - 1; i++) {
					printf("%04x ", tmpinfo[i]);
				}
				printf("\n");
			}

			ns3info++;
			break;
		default:	/* Data record */
			if (opt_verbose) {
				printf("  S3 datarec, line=%04d addr=0x%08lx len=%03ld\n", 
					line, tmprec.addr, tmprec.len);
			}
			s3data[ns3data].addr = tmprec.addr;
			s3data[ns3data].len = tmprec.len;
			s3data[ns3data].checksum = tmprec.checksum;
			s3data[ns3data].data = malloc(tmprec.len);
			for ( i = 0; i < tmprec.len; i++) {
				memcpy(tmpbuf, buf+S3DATA_TXTOFFSET+(i*2), 2);
				tmpbuf[2] = '\0';
				s3data[ns3data].data[i] = strtoul(tmpbuf, NULL, 16);
			}
			ns3data++;
			break;
		}
	}
	return result;
}


/*----------------------------------------------------------------
* str2macaddr
* This function converts a character string that represents an
* a 6 byte hex string to a 6 byte array.
* The string format is: "xx:xx:xx:xx:xx:xx"
*
* Arguments:
*	a	- a six byte array
*	s	- character string representing a mac address
* Returns: 
*	0	success
*	~0	detected a format error
----------------------------------------------------------------*/
int str2macaddr( UINT8 *a, char *s )
{
	char	*p;
	int	i;
	UINT	val;

	for ( i = 0; i < 5; i++) {  /* loop over the number of :'s */
		p = strchr( s, ':');
		if ( p == NULL ) {
			return 1;
		} else {
			*p = '\0';
			sscanf( s, "%x", &val);
			a[i] = (UINT8)val;
			s = p+1;
		}
	}
	sscanf( s, "%x", &val);
	a[i] = (UINT8)val;
	return 0;
}


/*----------------------------------------------------------------
* s3datarec_compare
*
* Comparison function for qsort().
*
* Arguments:
*	p1	ptr to the first item
*	p2	ptr to the second item
* Returns: 
*	0	items are equal
*	<0	p1 < p2
*	>0	p1 > p2
----------------------------------------------------------------*/
int s3datarec_compare(const void *p1, const void *p2) 
{
	const s3datarec_t	*s1 = p1;
	const s3datarec_t	*s2 = p2;
	if ( s1->addr == s2->addr ) return 0;
	if ( s1->addr < s2->addr ) return -1;
	return 1;
}


/*----------------------------------------------------------------
* usage
*
* This function displays the proper command line syntax of this 
* utility.
*
* Arguments:
*	none
*
* Returns:
*	nothing
----------------------------------------------------------------*/
void usage(void)
{
	printf("\n%s : 802.11 frame dump utility\n", appname);
	printf("    usage: %s [option ...] devname\n\n", appname);
	printf("       where valid options are:\n\n"
"  options:  (pnemonics in parentheses)\n"
"       GENERAL OPTIONS:\n"
"       -v          (verbose)  Show more status info during operation.\n"
"       -V          (Version)  Show version and exit\n"
"       -n          (nowrite)  Do all processing, including card PDA read, \n"
"                              but do not write to card.\n"
"       -d          (debug)    Do all processing, excluding card PDA read, \n"
"                              but do not write to card.  A valid interface \n"
"                              name is _not_ required for this mode.\n"
"       -s          (status)   Show CIS, PDA from card and exit\n"
"       -g          (generate) Show the PDA in a format readable by this \n"
"                              program.  Useful for saving the existing PDA\n"
"                              from a card.\n"
"\n"
"       IMAGEFILE OPTIONS:\n"
"       -r <file>   (ram)      Load SREC file to card RAM.  This option may\n"
"                              be specified multiple times.  If the value \n"
"                              is \"stdin\", the file will be read from \n"
"                              stdin and the option may only be specified once.\n"
"       -f <file>   (flash)    Load SREC file to card FLASH. This option may\n"
"                              be specified multiple times.  If the value \n"
"                              is \"stdin\", the file will be read from \n"
"                              stdin and the option may only be specified once.\n"
"\n"
"       PDA OPTIONS:\n"
"       -a <file>   (addpdr)   Add the PDRs from file to the PDA from card. This\n"
"                              option may be specified multiple times.\n"
"       -p <file>   (pda)      Replace the card PDA with the contents of file.\n"
"       -m <haddr>  (macaddr)  Overwrite the MAC address PDR with the given \n"
"                              value.  <addr> ::= xx:xx:xx:xx:xx:xx, where \n"
"                              xx is a two digit hex number.\n"
"       -S <str>    (Sernum)   Overwrite the serial number PDR with the given\n"
"                              string.  String must be <= 12 characters, any\n"
"                              extra will be truncated.\n"
"       -l <addr>   (pdaloc)   PDA location in card memory.  Commonly values:\n"
"                                 HFA3841 ==> 0x003f0000\n"
"                                 HFA3842 ==> 0x007f0000\n"
"\n"
"  argument:\n"
"  	devname    Linux device name (e.g. eth0, wlan0)\n"
"\n"
"EXAMPLES:\n"
"   Review card status:\n"
"     prism2dl -s wlan0\n"
"\n"
"   Load a new PDA:\n"
"     prism2dl -p pdafile.txt wlan0\n"
"       or\n"
"     prism2dl -p pdafile.txt -a pda1.txt -a pda2.txt wlan0\n"
"\n"
"     Note that the f/w images will most likely contain bogus plug info after\n"
"     rewriting the PDA by itself.  It is generally recommended to reload the \n"
"     primage and secondary images at the same time as modifying the PDA.\n"
"\n"
"   Load a FLASH image _and_ PDA:\n"
"     prism2dl -p pdafile.txt -f CIS.hex -f primary.hex -f secondary.hex wlan0\n"
"\n"
"   Load a RAM image:\n"
"     prism2dl -a pda1.txt -r tertiary.hex\n"
"\n"
"Note: PDA records are additive starting with the records from the card\n"
"      OR the records from the -p specified file.  -a specified file(s)\n"
"      overwrite, append, or remove records one at a time.  If multiple\n"
"      files are specified using the -a option, the files are processed\n"
"      from left to right.  This implies that a record removed from the\n"
"      current working PDA may then be added again by a record that\n"
"      appears after the \"remove\" record in the file set.\n\n");

}


/*----------------------------------------------------------------
* writeimage
*
* Takes the chunks, builds p80211 messages and sends them down
* to the driver for writing to the card.
*
* Arguments:
*	fchunk		Array of image chunks
*	nfchunks	Number of image chunks
*	isflash		boolean indicating whether this is a
*                       flash write or a ram write.
*
* Returns: 
*	0	success
*	~0	failure
----------------------------------------------------------------*/
int writeimage(imgchunk_t *fchunk, UINT nfchunks, int isflash)
{
	int					result = 0;
	p80211msg_p2req_flashdl_state_t		fstatemsg;
	p80211msg_p2req_flashdl_write_t		fwritemsg;
	p80211msg_p2req_ramdl_state_t		rstatemsg;
	p80211msg_p2req_ramdl_write_t		rwritemsg;
	p80211msg_t				*msgp;
	UINT32					resultcode;
	int					i;
	int					j;
	UINT					nwrites;
	UINT32					curroff;
	UINT32					currlen;
	UINT32					currdaddr;

	/* Initialize the messages */
	memset(&fstatemsg, 0, sizeof(fstatemsg));
	strcpy(fstatemsg.devname, devname);
	fstatemsg.msgcode =		DIDmsg_p2req_flashdl_state;
	fstatemsg.msglen =		sizeof(fstatemsg);
	fstatemsg.enable.did =		DIDmsg_p2req_flashdl_state_enable;
	fstatemsg.resultcode.did =	DIDmsg_p2req_flashdl_state_resultcode;
	fstatemsg.enable.status =	P80211ENUM_msgitem_status_data_ok;
	fstatemsg.resultcode.status =	P80211ENUM_msgitem_status_no_value;
	fstatemsg.enable.len =		sizeof(UINT32);
	fstatemsg.resultcode.len =	sizeof(UINT32);

	memset(&fwritemsg, 0, sizeof(fwritemsg));
	strcpy(fwritemsg.devname, devname);
	fwritemsg.msgcode =		DIDmsg_p2req_flashdl_write;
	fwritemsg.msglen =		sizeof(fwritemsg);
	fwritemsg.addr.did =		DIDmsg_p2req_flashdl_write_addr;
	fwritemsg.len.did =		DIDmsg_p2req_flashdl_write_len;
	fwritemsg.data.did =		DIDmsg_p2req_flashdl_write_data;
	fwritemsg.resultcode.did =	DIDmsg_p2req_flashdl_write_resultcode;
	fwritemsg.addr.status =		P80211ENUM_msgitem_status_data_ok;
	fwritemsg.len.status =		P80211ENUM_msgitem_status_data_ok;
	fwritemsg.data.status =		P80211ENUM_msgitem_status_data_ok;
	fwritemsg.resultcode.status =	P80211ENUM_msgitem_status_no_value;
	fwritemsg.addr.len =		sizeof(UINT32);
	fwritemsg.len.len =		sizeof(UINT32);
	fwritemsg.data.len =		WRITESIZE_MAX;
	fwritemsg.resultcode.len =	sizeof(UINT32);

	memset(&rstatemsg, 0, sizeof(rstatemsg));
	strcpy(rstatemsg.devname, devname);
	rstatemsg.msgcode =		DIDmsg_p2req_ramdl_state;
	rstatemsg.msglen =		sizeof(rstatemsg);
	rstatemsg.enable.did =		DIDmsg_p2req_ramdl_state_enable;
	rstatemsg.exeaddr.did =		DIDmsg_p2req_ramdl_state_exeaddr;
	rstatemsg.resultcode.did =	DIDmsg_p2req_ramdl_state_resultcode;
	rstatemsg.enable.status =	P80211ENUM_msgitem_status_data_ok;
	rstatemsg.exeaddr.status =	P80211ENUM_msgitem_status_data_ok;
	rstatemsg.resultcode.status =	P80211ENUM_msgitem_status_no_value;
	rstatemsg.enable.len =		sizeof(UINT32);
	rstatemsg.exeaddr.len =		sizeof(UINT32);
	rstatemsg.resultcode.len =	sizeof(UINT32);

	memset(&rwritemsg, 0, sizeof(rwritemsg));
	strcpy(rwritemsg.devname, devname);
	rwritemsg.msgcode =		DIDmsg_p2req_ramdl_write;
	rwritemsg.msglen =		sizeof(rwritemsg);
	rwritemsg.addr.did =		DIDmsg_p2req_ramdl_write_addr;
	rwritemsg.len.did =		DIDmsg_p2req_ramdl_write_len;
	rwritemsg.data.did =		DIDmsg_p2req_ramdl_write_data;
	rwritemsg.resultcode.did =	DIDmsg_p2req_ramdl_write_resultcode;
	rwritemsg.addr.status =		P80211ENUM_msgitem_status_data_ok;
	rwritemsg.len.status =		P80211ENUM_msgitem_status_data_ok;
	rwritemsg.data.status =		P80211ENUM_msgitem_status_data_ok;
	rwritemsg.resultcode.status =	P80211ENUM_msgitem_status_no_value;
	rwritemsg.addr.len =		sizeof(UINT32);
	rwritemsg.len.len =		sizeof(UINT32);
	rwritemsg.data.len =		WRITESIZE_MAX;
	rwritemsg.resultcode.len =	sizeof(UINT32);

	/* Send xxx_state(enable) */
	if (opt_verbose) printf("Sending dl_state(enable) message.\n");
	if ( isflash ) {
		fstatemsg.enable.data = P80211ENUM_truth_true;
	} else {
		rstatemsg.enable.data = P80211ENUM_truth_true;
		rstatemsg.exeaddr.data = startaddr;
	}
	if ( !opt_debug ) {
		msgp = isflash ? (p80211msg_t*)&fstatemsg : (p80211msg_t*)&rstatemsg;
		result = do_ioctl(msgp);
		if ( result ) {
			fprintf(stderr,APPNAME
				": writeimage()->do_ioctl() failed w/ result=%d, "
				"aborting download\n", result);
			return result;
		}
		resultcode = isflash ? 
				fstatemsg.resultcode.data : rstatemsg.resultcode.data;
		if ( resultcode != P80211ENUM_resultcode_success ) {
			fprintf(stderr,APPNAME
				": writeimage()->xxxdl_state msg indicates failure, "
				"w/ resultcode=%ld, aborting download.\n",
				resultcode);
			return 1;
		}
	}

	/* Now, loop through the data chunks and send WRITESIZE_MAX data */
	for ( i = 0; i < nfchunks; i++) {
#if 0
FILE *fp;
char fname[80];
#endif
		nwrites = fchunk[i].len / WRITESIZE_MAX;
		nwrites += (fchunk[i].len % WRITESIZE_MAX) ? 1 : 0;
		curroff = 0;
#if 0
sprintf(fname, "d%06lx.dat", fchunk[i].addr);
fp = fopen( fname, "w");
#endif
		for ( j = 0; j < nwrites; j++) {
			currlen = 
			  (fchunk[i].len - (WRITESIZE_MAX * j)) > WRITESIZE_MAX ?
			  WRITESIZE_MAX :
			  (fchunk[i].len - (WRITESIZE_MAX * j));
			curroff = j * WRITESIZE_MAX;
			currdaddr = fchunk[i].addr + curroff;
			/* Setup the message */
			if ( isflash ) {
				fwritemsg.addr.data = currdaddr;
				fwritemsg.len.data = currlen;
				memcpy(fwritemsg.data.data, 
					fchunk[i].data + curroff,
					currlen);
#if 0
fwrite(fwritemsg.data.data, 1, currlen, fp);
#endif
			} else {
				rwritemsg.addr.data = currdaddr;
				rwritemsg.len.data = currlen;
				memcpy(rwritemsg.data.data, 
					fchunk[i].data + curroff,
					currlen);
#if 0
fwrite(rwritemsg.data.data, 1, currlen, fp);
#endif
			}
			/* Send flashdl_write(pda) */
			if (opt_verbose) {
				printf("Sending xxxdl_write message addr=%06lx len=%ld.\n",
					currdaddr, currlen);
			}

			if ( opt_debug ) continue;

			msgp = isflash ? (p80211msg_t*)&fwritemsg : (p80211msg_t*)&rwritemsg;
			result = do_ioctl(msgp);
	
			/* Check the results */
			if ( result ) {
				fprintf(stderr,APPNAME
					": writeimage()->do_ioctl() failed w/ result=%d, "
					"aborting download\n", result);
				return result;
			}
			resultcode = isflash ? 
				fstatemsg.resultcode.data : rstatemsg.resultcode.data;
			if ( resultcode != P80211ENUM_resultcode_success ) {
				fprintf(stderr,APPNAME
					": writeimage()->xxxdl_write msg indicates failure, "
					"w/ resultcode=%ld, aborting download.\n",
					resultcode);
				return 1;
			}
		}
#if 0
fclose(fp);
#endif
	}

	/* Send xxx_state(disable) */
	if (opt_verbose) printf("Sending dl_state(disable) message.\n");
	if ( isflash ) {
		fstatemsg.enable.data = P80211ENUM_truth_false;
	} else {
		rstatemsg.enable.data = P80211ENUM_truth_false;
		rstatemsg.exeaddr.data = 0;
	}

	if ( opt_debug ) return result;

	msgp = isflash ? (p80211msg_t*)&fstatemsg : (p80211msg_t*)&rstatemsg;
	result = do_ioctl(msgp);
	if ( result ) {
		fprintf(stderr,APPNAME
			": writeimage()->do_ioctl() failed w/ result=%d, "
			"aborting download\n", result);
		return result;
	}
	resultcode = isflash ? 
			fstatemsg.resultcode.data : rstatemsg.resultcode.data;
	if ( resultcode != P80211ENUM_resultcode_success ) {
		fprintf(stderr,APPNAME
			": writeimage()->xxxdl_state msg indicates failure, "
			"w/ resultcode=%ld, aborting download.\n",
			resultcode);
		return 1;
	}
	return result;
}


/*----------------------------------------------------------------
* dumpchunks
*
* Dumps the chunk info for each chunk of the current set to stdout.
* 
*
* Arguments:
*	fchunk		Array of image chunks
*	nfchunks	Number of image chunks
*
* Returns: 
*	0	success
*	~0	failure
----------------------------------------------------------------*/
void dumpchunks( imgchunk_t *fchunk, UINT nfchunks)
{
	int	i;
	int	j;

	for ( i = 0; i < nfchunks; i++) {
		printf("\nChunk %d: addr=0x%08lx  len=%ld  crc=%04hx\n",
			i, fchunk[i].addr, fchunk[i].len, fchunk[i].crc);
		printf("%08lx: ", fchunk[i].addr);
		for(j = 0; j < fchunk[i].len; j++) {
			printf("%02x ", fchunk[i].data[j]);
			if (((j+1) % 16) == 0) {
				printf("\n%08lx: ", fchunk[i].addr + j + 1);
			}
		}
	}
	printf("\n");
}

int validate_identity(void) 
{
	int i;
	int result = 1;

	printf("NIC ID: %#x v%d.%d.%d\n", 
	       nicid.id,
	       nicid.major,
	       nicid.minor,
	       nicid.variant);
	printf("MFI ID: %#x v%d %d->%d\n", 
	       rfid.id,
	       rfid.variant,
	       rfid.bottom,
	       rfid.top);
	printf("CFI ID: %#x v%d %d->%d\n", 
	       macid.id,
	       macid.variant,
	       macid.bottom,
	       macid.top);
	printf("PRI ID: %#x v%d %d->%d\n",
	       priid.id,
	       priid.variant,
	       priid.bottom,
	       priid.top);

	for (i = 0 ; i < ns3info ; i ++) {
		switch (s3info[i].type) {
		case 1:
			printf("Version:  ID %#x %d.%d.%d\n", 
			       s3info[i].info.version.id,
			       s3info[i].info.version.major,
				       s3info[i].info.version.minor,
			       s3info[i].info.version.variant);
			break;
		case 2:
			printf("Compat: Role %#x Id %#x v%d %d->%d\n",
			       s3info[i].info.compat.role,
			       s3info[i].info.compat.id,
			       s3info[i].info.compat.variant,
			       s3info[i].info.compat.bottom,
			       s3info[i].info.compat.top);

			/* MAC compat range */
			if ((s3info[i].info.compat.role == 1) &&
			    (s3info[i].info.compat.id == 2)) {
				if (s3info[i].info.compat.variant != 
				    macid.variant) {
					result = 2;
				}	
			}
		
			/* PRI compat range */
			if ((s3info[i].info.compat.role == 1) &&
			    (s3info[i].info.compat.id == 3)) {
				if ((s3info[i].info.compat.bottom > priid.top) ||
				    (s3info[i].info.compat.top < priid.bottom)){
					result = 3;
				}					
			}
			/* SEC compat range */
			if ((s3info[i].info.compat.role == 1) &&
			    (s3info[i].info.compat.id == 4)) {
				
			}

			break;
		case 3:
				printf("Seq: %#x\n", s3info[i].info.buildseq);
				
				break;
		case 4:
			printf("Platform:  ID %#x %d.%d.%d\n", 
			       s3info[i].info.version.id,
			       s3info[i].info.version.major,
			       s3info[i].info.version.minor,
			       s3info[i].info.version.variant);

			if (nicid.id != s3info[i].info.version.id)
				continue;
			if (nicid.major != s3info[i].info.version.major)
				continue;
			if (nicid.minor != s3info[i].info.version.minor)
				continue;
			if ((nicid.variant != s3info[i].info.version.variant) &&
			    (nicid.id != 0x8008))
				continue;

			if (result != 2)
				result = 0;
			break;
		case 0x8001:
			printf("name inforec len %d\n", s3info[i].len);
			
			break;
		default:
			printf("Unknown inforec type %d\n", s3info[i].type);
		}
	}
	// walk through 

	return result;
}
