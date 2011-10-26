/*
 * uCheader.h:  uCbootstrap header specification
 *
 * NOTE that this is provided here only for reference.
 *      The primary authority for this is the kernel
 *      include file: include/asm-m68knommu/uCbootstrap.h
 *
 * (c) 2004-2008 Arcturus Networks Inc.
 *     June 2008, David Wu added uCheader version 0.3
 *          by Michael Leslie et al. <www.arcturusnetworks.com>
 *
 */

#if !defined (_UCHEADER_H_)
#define _UCHEADER_H_

#define _UCHEADER_VERSION_ 0.3

/* The uCimage_header structure gets appended to the image file
 * before transmission to the uCbootstrap platform, and is
 * parsed by uCbootstrap upon reception of the image:
 *
 * Note that integers in images are by definition LITTLE ENDIAN
 */
typedef struct {
	unsigned char magic[8];	/* magic number "uCimage\0" */
	int header_size;	/* after which data begins */
	int data_size;		/* size of image in bytes */
	char datecode[12];	/* output of 'date -I': "yyyy-mm-dd" */
	unsigned char md5sum[16];	/* binary md5sum of data */
	char name[128];		/* filename or ID */
	int bit32sum;		/* 32 bit checksum for data fields */
	char partition;		/* partition number */
	char padding[79];	/* pad to 256 bytes */
} uCimage_header;

typedef uCimage_header uCimage_header_v02;

#define UCHEADER_MAGIC "uCimage\0"	/* including one terminating zero */

/* The uCimage_header_cache structure is a smaller version of the
 * complete image header, containing only what is necessary for
 * handling of the image after it has been received.
 */
typedef struct {
	char valid;		/* = 0 => no data; = 1 => valid data in cache */
	int data_size;		/* size of image in bytes */
	char datecode[12];	/* output of 'date -I': "yyyy-mm-dd" */
	unsigned char md5sum[16];	/* binary md5sum of data */
	char name[128];		/* filename or ID */
	void *data;		/* point to data */
} uCimage_header_cache;

typedef struct {
        unsigned char magic[8]; /* magic number "uCimage\0" */
        int header_size;        /* after which data begins; not used in old version */
        int data_size;          /* size of image in bytes */
        char datecode[12];      /* output of 'date -I': "yyyy-mm-dd" */
        unsigned char md5sum[16];       /* binary md5sum of data */
        char name[128];         /* filename or ID */
        int bit32sum;           /* 32 bit checksum for data fields */
        char partition;         /* first/default partition number used for creation this partition if it does
                                   not exist; if it exists then checking if the flash_start_address is valid
                                 */
        unsigned char version[2];
                                 /* major.minor cannot be 0.0 or 255.255 otherwise it's an old  uCheader */
        char reserved1[1];       /* set to 0 */

        unsigned int A_flash_start_address;  /* absolute address to write to Flash for partition "partition"*/
        unsigned int A_start;        /* offset to end of header == header_size */
        unsigned int A_length;       /* size of this image */
        unsigned int A_feature:24;   /* 1 - 254 valid features */
        unsigned int A_partition:8;  /* a letter, same as in bootloader, valid when bit7 is 0*/

        unsigned int B_flash_start_address;  /* absolute address to write to Flash for partition "partition"*/
        unsigned int B_start;        /* offset to end of header */
        unsigned int B_length;       /* size of this image */
        unsigned int B_feature:24;   /* 24 bits execlude 0 and 0xFFFFFF */
        unsigned int B_partition:8;  /* a letter, same as in bootloader, valid when bit7 is 0*/

        unsigned int C_offset;       /* should be end of B, i.e B_start + B_length 
                                      * if B does not exist then A_start + A_length
                                      */
        char reserved2[38];
        unsigned short header_checksum;  /* checksum for header itself; recalcute checksum
                                            * with checksum in should get a result of 0
                                            */
} uCimage_header_v03;
/*
 this bit map is only used for generating the features, not used as a mask to check it.
 0 or FFs is not a valid feature. 
    bit                                   bit
     7     6     5     4       3   2   1   0
     ^-----^-----^-----^-------^---^---^---^
     |     |     |     |       |   |   |   WF(0)
     |     |     |     |       |   |  WFC(1)
     |     |     |     |       |  PRE(2)
     |     |     |     |     POST(3)
     |     |     | RAM_LOADER(4)
     |     | COPY_TO_RAM(5)
     |  MOUNT(6)
    RW/RO
*/
/* PRE, COPY, EXEC, WTF@PART, WRT@ADDR, POST*/
/* when write to Flash, if a partition needs to be created, it should be
  "RW" -- if bit 7 is 0
  "RO" -- if bit 7 is 1
 */

enum 
{
 /* write to partition only, fail when cannot write to */
FWRITE_TO_FLASH_PARTITION = 0x1,

 /* write image directly to Flash at start_address without checking partition number
  * but it needs to erase sectors basing on the data_size in the header. It may
  * need to check the Flash size and round up to sector boundary.  
  * The created partition has a "RW" permission.
  * Ex. sprintf(buf, "_%c=%x:%x:RW", partition, address, length)
  */
FWRITE_TO_FLASH_ADDR = 0x2,

#if 0
 /* write image to Flash when partition and start_address match the current settings */
FWRITE_TO_FLASH_WITH_CONDITION = 0x3,
#endif

 /* condition for mount: only mount when offset is not zero, which means offset >= header_size
  * if by any reason it fails to mount then no further action should be taken.
  */
 /* mount and execute a shell script or binary (pre action)then program the image
  * into partition
  */
FWRITE_TO_FLASH_PRE = 0x5,
 /* similar to FWRITE_TO_FLASH_PRE but program the image first then execute a shell script or binary */
FWRITE_TO_FLASH_POST = 0x9,

 /* similar to FWRITE_TO_FLASH_PRE, mount and execute a shell script or binary first, then program the image,
  * and next execute another shell script or binary (post action)
  */
FWRITE_TO_FLASH_PRE_AND_POST = 0xd,

#if 0
 FWRITE_TO_FLASH_PRE_WITH_CONDITION = 0x7,
 FWRITE_TO_FLASH_POST_WITH_CONDITION = 0xb,
 FWRITE_TO_FLASH_PRE_POST_WITH_CONDITION = 0xf,
/*FRAM_LOADER_PRE = 0x14,*//* mount image at u.B and run pre then call ramloader with
                           * image at u.A with data_size size
                           */
#endif

FRAM_LOADER = 0x10,       /* load the image into RAM and pass it to bootloader (goram) */
FCOPY_TO_RAM = 0x20,      /* copy the image to RAM with name ? */
FCOPY_TO_RAM_EXEC = 0x21, /* copy the image at RAM and execute it */

#if 0  /* not supported */
 FCOPY_TO_RAM_EXEC_PRE = 0x22, /* copy the image at u.A to ram and run pre then execute it */
 FCOPY_TO_RAM_EXEC_POST = 0x23, /* copy the image at u.A to ram and run pre then execute it */
 FCOPY_TO_RAM_EXEC_PRE_POST = 0x2c, /* copy the image at u.A to ram and run pre, execute it, then run post */
 FCOPY_TO_RAM_PRE = 0x24,  /* mount image at u.B and run pre, then copy the image at u.A to
                           * ram and name it to "path" in header
                           */
 FCOPY_TO_RAM_POST = 0x28, /* mount image at u.B and copy the image at u.A to ram, name it to
                           * "path" and run post
                           */
#endif

FMOUNT = 0x40,            /* mount only : mounting point is DEFAULT_MNT */
FMOUNT_PRE = 0x44,        /* mount and run PRE */
FMOUNT_POST = 0x48,       /* mount and run POST */

};

#define DEFAULT_ADDR 0xFFFFFFFF
#define DEFAULT_PART 0xFF  /* not '0' */
#define DEFAULT_FEATURE 0x0   /* no feature */
#define DEFAULT_MNT "/mnt"

#if 0
/* ie. internal to header.c, external elsewhere: */
#if defined (_UCHEADER_DECLS_)
#  define EXTERN
#else
#  define EXTERN extern
#endif

/****** function prototypes: ************************************************/

/* Check addr 'codebuf' for uCimage header */
EXTERN int check_header(void);

/* Check md5 at 'buf' against 16 byte *digest */
EXTERN int check_md5(char *buf, unsigned char *digest, int size);

/* convert 32 char md5 ascii and translate to 16 bytes at *digest */
EXTERN int MD5_ascii_to_bin(char *ascii, char *digest);

/****** data declarations: **************************************************/

EXTERN int ram_image_present;	/* may or may not have a uCimage header */
EXTERN int ram_image_header_present;	/* note that necessarily ram_image_present */

EXTERN uCimage_header *header;	/* points to received header,
				 * initially at *codebuf */
EXTERN uCimage_header_cache header_cache;	/* local cache of relevant header bits */


#undef EXTERN

extern int check_partition_md5(int partition);

#endif /* 0 */

#endif				/* _UCHEADER_H_ */
