/* probe.c -- BIOS probes */
/*
Copyright 1999-2006 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

/*#define DEBUG_PROBE*/
#define BITMAP 0	/* change to 1 when do_bitmap is filled in */
#define VOLID  1	/* change to 1 when do_volid is filled in */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "lilo.h"
#include "common.h"
#include "device.h"
#include "geometry.h"
#include "partition.h"
#include "bsect.h"
#include "bdata.h"
#include "probe.h"


#ifdef LCF_BDATA
#if BD_MAX_FLOPPY > 4
#error "too many floppies in  bdata.h"
#endif
#if BD_MAX_HARD > 16
#error "too many hard disks in  bdata.h"
#endif
#if BD_GET_VIDEO > 3
#error "video get level set too high in  bdata.h"
#endif
#endif


static union Buf {
   unsigned char b[5*SECTOR_SIZE];
   struct {
      short checksum[2];	/* prevent alignment on *4 boundary */
      char signature[4];
      short version;
      short length;
      unsigned char disk;	/* device code of last good disk */
      unsigned char vid, mflp, mhrd;
      short floppy;		/* byte offset to floppy data    */
      short hard;		/* byte offset to hard disk data */
      short partitions;		/* byte offset to partition info */
      video_t v;
      floppy_t f[4];
      hard_t d;
/*      edd_t edd; */
   } s4;
   struct {
      short checksum[2];	/* prevent alignment on *4 boundary */
      char signature[4];
      short version;
      short length;
      unsigned char disk;	/* device code of last good disk */
      unsigned char vid, mflp, mhrd;
      short floppy;		/* byte offset to floppy data    */
      short hard;		/* byte offset to hard disk data */
      short partitions;		/* byte offset to partition info */
/* version 5 additions	*/
      short equipment;		/* byte offset to the equipment information */
      short video;		/* byte offset to the video information */
   } s5;
} buf;

static equip_t *eq;
static video_t1 *v1;
static video_t2 *v2;
static video_t25 *v25;	/* extension for PROBE_VERSION 5 */
static video_t3 *v3;

static int video_36_bug;
static int buf_valid = -1;
static hard_t *hdp[16+1] =		/* pointers to all the hard disks */
	{	NULL, NULL, NULL, NULL, 
		NULL, NULL, NULL, NULL, 
		NULL, NULL, NULL, NULL, 
		NULL, NULL, NULL, NULL,  NULL	};
static char warned[16];

static void do_ebda(void);
static void do_cr_pr(void);
static void do_help(void);
static void do_geom(char *bios);
static void do_geom_all(void);
static void do_table(char *part);
static void do_video(void);
static void do_bios(void);
#if BITMAP
static void do_bitmap(char *file);
#endif
#if VOLID
static void do_volid(void);
#endif
static char dev[] = "<device>";

extern CHANGE_RULE *change_rules;	/* defined in partition.c */



static
struct Probes {
	char *cmd;
	void (*prc)();
	char *str;
	char *help;
	}
	list[] = {
{ "help",  do_help,  NULL,  "Print list of -T(ell) options"	},
{ "bios",  do_bios,  NULL,  "State of DL as passed to boot loader"  },
#if BITMAP
{ "bitmap=",do_bitmap,"<file>", "Display .bmp file X,Y/color/timer information"},
#endif
{ "ChRul", do_cr_pr, NULL,  "List partition change-rules"  },
{ "EBDA",  do_ebda,  NULL,  "Extended BIOS Data Area information" },
{ "geom=", do_geom,  "<bios>", "Geometry CHS data for BIOS code 0x80, etc." },
{ "geom" , do_geom_all, NULL, "Geometry for all BIOS drives" },
{ "table=", do_table, dev, "Partition table information for " DEV_DISK_DIR "/hda, etc."},
{ "video", do_video, NULL,  "Graphic mode information" },
#if VOLID
{ "vol-ID", do_volid, NULL, "Volume ID check for uniqueness"},
#endif
{ NULL,    NULL,     NULL,   NULL}
	};


static struct partitions {
	char *name;
	unsigned char type;
	unsigned char hide;
	} ptab [] = {		/* Not complete, by any means */

    { "DOS12", PART_DOS12, HIDDEN_OFF },
    { "DOS16_small", PART_DOS16_SMALL, HIDDEN_OFF },
    { "DOS16_big", PART_DOS16_BIG, HIDDEN_OFF },
    { "NTFS or OS2_HPFS", PART_NTFS, HIDDEN_OFF },	/* same as HPFS; keep these two together */
/*  { "HPFS", PART_HPFS, HIDDEN_OFF },	*/	/* same as NTFS */
    { "FAT32", PART_FAT32, HIDDEN_OFF },
    { "FAT32_lba", PART_FAT32_LBA, HIDDEN_OFF },
    { "FAT16_lba", PART_FAT16_LBA, HIDDEN_OFF },
    { "OS/2 BootMgr", PART_OS2_BOOTMGR, 0 },
    { "DOS extended", PART_DOS_EXTD, 0 },
    { "WIN extended", PART_WIN_EXTD_LBA, 0 },
    { "Linux ext'd", PART_LINUX_EXTD, 0 },
    { "Linux Swap", PART_LINUX_SWAP, 0 },
    { "Linux Native", PART_LINUX_NATIVE, 0 },
    { "Minix", PART_LINUX_MINIX, 0 },
    { "Linux RAID", 0xfd, 0 },
    { NULL, 0, 0 }   };

static char phead[] = "\t\t Type  Boot      Start           End      Sector    #sectors";
static int dirty = -1;	/* buffer is unread */

/* load the low memory bios data area */
/*  0 = no error, !0 = error on get */
int fetch(void)
{
    int fd;
    int got, get;
    int at = 0, seek = PROBESEG*16;
    
    if (buf_valid>=0) return buf_valid;
    
    if ((fd=open(DEV_DIR "/mem", O_RDONLY)) < 0) return buf_valid=1;
    at = lseek(fd, seek, SEEK_SET);
    if (at != seek) return buf_valid=1;
    get = sizeof(buf.b);
    if (read(fd, &buf.b, get) != get) return buf_valid=1;
    close(fd);
    dirty = 0;	/* buffer is unmodified */
    
    if (strncmp(buf.s5.signature, PROBE_SIGNATURE,4)) return buf_valid=2;
/*    got = buf.s5.version; */	/* quiet GCC */
    if (buf.s5.version < 3 ||
        buf.s5.version > (short)(PROBE_VERSION)) return buf_valid=3;
    got = buf.s5.length;
    if (got > sizeof(buf.b) || got < sizeof(buf.s4)) return buf_valid=4;
    if (*(int*)buf.s5.checksum != crc32((unsigned char*)&buf.s5 + 4, got-4, CRC_POLY1))
    	return buf_valid=5;

    if (buf.s5.version == 4) {
	eq = (void*)&buf.s4.v.equipment;
	v1 = (void*)&buf.s4.v.vid0F;
	if (buf.s4.vid > 1) v2 = (void*)&buf.s4.v.vid12;
	if (buf.s4.vid > 2) v3 = (void*)&buf.s4.v.vid4F00;
    }
    if (buf.s5.version >= 5) {
	eq = (void*)&buf.b[buf.s5.equipment];
	v1 = (void*)&buf.b[buf.s5.video];
	if (buf.s5.vid > 1) {
	    v2 = (void*)v1 + sizeof(*v1);
	    v25 = (void*)v2 + sizeof(*v2);
	}
	if (buf.s5.vid > 2) v3 = (void*)v25 + sizeof(*v25);
    }
#if BETA_TEST
	if (verbose>=5) printf("fetch: good return\n");
#endif    
    return buf_valid=0;
}


int purge(void)
{
    int i, fd;
    int seek = PROBESEG*16;
    
    if (verbose>=6) printf("purge: called\n");
#if 0
    if (verbose>=6) {fetch(); dirty=1;}		/* test of checksumming */
#endif
    if (dirty <= 0) return 0;		/* nothing to purge */
    
    if ((i=fetch())) return i;	/* return error from fetch */
    
    i = buf.s5.length;
    *(int*)buf.s5.checksum = crc32((unsigned char*)&buf.s5 + 4, i-4, CRC_POLY1);
    
    if ((fd=open(DEV_DIR "/mem", O_WRONLY)) < 0) pdie("purge: can't open " DEV_DIR "/mem");
    if (lseek(fd, seek, SEEK_SET) != seek) pdie("purge: ");
    i = sizeof(buf.b);
    if (write(fd, &buf.b, i) != i) pdie("purge: ");
    close(fd);
    
    if (verbose>=6) printf("purge: successful write\n");
    
    return dirty = 0;			/* buffer is unmodified */
}


static int notice(int needed)
{
    int f = fetch();
    
    if (f || buf.s5.version < needed) {
	printf( f==1 ?  "Only 'root' may do this.\n\n" :
#if 0
		"This information request requires that you previously booted your system\n"
		"using LILO version %s or later.  These versions of the LILO boot\n"
		"loader provide the BIOS data check information in low memory.  A boot floppy\n"
		"constructed with 'mkrescue' may help.\n\n",
#endif
		"The information you requested is not available.\n\n"
		"Booting your system with LILO version %s or later would provide the re-\n"
		"quested information as part of the BIOS data check.  Please install a more\n"
		"recent version of LILO on your hard disk, or create a bootable rescue floppy\n"
		"or rescue CD with the 'mkrescue' command.\n\n",
		
		needed==4 ? "22.0" :
		needed==5 ? "22.5.1" :
		needed==6 ? "22.5.7" :
		S(VERSION_MAJOR) "." S(VERSION_MINOR) VERSION_EDIT  );
	return 1;
    }
    return 0;
}


/* print out the help page for -T flag */
static void do_help(void)
{
    struct Probes *pr;
    
    printf("usage:");
    for (pr=list; pr->cmd; pr++) {
    	printf("\tlilo -T %s%s\t%s\n", 
    			pr->cmd, 
    			pr->str ? pr->str : "        ",
    			pr->help);
    }
#ifdef DEBUG_PROBE
    printf("    In some cases, the '-v' flag will produce more output.\n");
    printf("sizeof(video_t) = %d  sizeof(floppy_t) = %d  sizeof(hard_t) = %d\n"
           "sizeof(edd_t) = %d  sizeof(buf.s) = %d\n",
            sizeof(video_t),  sizeof(floppy_t), sizeof(hard_t), sizeof(edd_t),
            sizeof(buf.s5) );
	
    printf("fetch returns %d\n", fetch());            
#endif
}

/* diagnostic output */
static void show_geom(char *who, int cyl, int head, int sect)
{
   if (nowarn) return;
   fprintf(errstd, "    %s: %d cylinders, %d heads, %d sectors\n", who, cyl, head, sect);
}


/* get the old BIOS disk geometry */
static int get_geom(unsigned int drive, struct disk_geom *geom)
{
    hard_t *hd;
    floppy_t *fd;
    int i;
    struct partition *pt_base;
    unsigned int total;
    int sec_err = 0;
    int hd_err = 0;

#if 0
    if((i=fetch())) {
        printf("No drive geometry information is available.\n\n");
        exit(0);
    }
#else
    if (notice(4)) exit(0);
#endif
#ifdef DEBUG_PROBE
	printf("get_geom: drive = 0x%02X\n", drive);
	fflush(stdout);
#endif
    if (drive >= 0 && drive < buf.s5.mflp) {
	fd = (floppy_t*)&buf.b[buf.s5.floppy] + drive;
	hd = (hard_t*)fd;
    }
    else if (drive == 0x80) {
	hdp[drive-0x80] = hd = (hard_t*)&buf.b[buf.s5.hard];
    }    
    else if (drive >= 0x81 && drive < 0x80+buf.s5.mhrd) {
	if (drive > buf.s5.disk) return 1;
	if (!hdp[drive-0x80]) {
	    i = get_geom(drive-1, geom);
#ifdef DEBUG_PROBE
		printf("get_geom recursive return = %d  AH=0x%02X\n", i, i-1);
		fflush(stdout);
#endif
	    if (i) return i;
	}
	hd = hdp[drive-0x80];
    } else return 1;
#ifdef DEBUG_PROBE
	printf("get_geom:  hd = %08X\n", (int)hd);
	fflush(stdout);
#endif
    
    memset(geom, 0, sizeof(*geom));


    if (drive >= 0x80)
        hdp[drive-0x80 + 1] = (void*)hd + sizeof(hard_t);		/* simplest increment, but may be wrong */
    
    /* regs.eax = 0x1500;           check drive type */
    /* regs.edx = drive;			*/

#ifdef DEBUG_PROBE
	printf("get_geom: int13, fn=15\n");
	fflush(stdout);
#endif
   
   if (hd->fn15.flags & 1)   return 1;	/* carry was set */
   geom->type = hd->fn15.ah;
   if (geom->type == 0) return 1;
   if (geom->type == 3)
     geom->n_total_blocks = ((int)hd->fn15.cx << 16) + hd->fn15.dx;
   
   /* regs.eax = 0x0800;		*/
   /* regs.edx = drive;			*/
   
#ifdef DEBUG_PROBE
	printf("get_geom: int13, fn=08\n");
	fflush(stdout);
#endif
   
   if (hd->fn08.flags&1 || hd->fn08.ah || hd->fn08.cx==0)
     return 1 + hd->fn08.ah;
   
   if (!(i = hd->fn08.cx & 0x3F))  i = 64;	/* BIOS bug if 0 */
   geom->n_sect = i;
   
   i *=
   geom->n_head = ((hd->fn08.dx>>8)&0xFF)+1;
   i *=
   geom->n_cyl  = (((hd->fn08.cx>>8)&0xFF)|((hd->fn08.cx&0xC0)<<2))+1;
   if (i > geom->n_total_blocks) geom->n_total_blocks = i;
   geom->n_disks = hd->fn08.dx & 0xFF;
   geom->pt = NULL;

   hd_err = (geom->n_head > 255);
   sec_err = (geom->n_sect > 63);
   
   if (drive < 4)  return 0;
   
   pt_base = NULL;
   if (buf.s5.disk) {
	pt_base = (struct partition *)&buf.b[buf.s5.partitions];
   }
   if (pt_base && drive <= (int)buf.s5.disk) {
#if 0
   				geom->pt = &pt_base[(drive&15)*4];
#else
	void *p = (void*)pt_base;
	int i = buf.s5.version >= 4 ? 8 : 0;
	
	p += (drive & 15) * (PART_TABLE_SIZE + i) + i;
	geom->pt = (struct partition *)p;
	if (i) geom->serial_no = *(int*)(p-6);
#endif
   }

#ifdef DEBUG_PROBE
   printf("get_geom:  PT->%08X  S/N=%08X\n", (int)geom->pt, geom->serial_no);
#endif
      
   /* regs.eax = 0x4100;      check EDD extensions present */
   /* regs.edx = drive;				*/
   /* regs.ebx = 0x55AA;			*/
#ifdef DEBUG_PROBE
	printf("get_geom: int13, fn=41\n");
	fflush(stdout);
#endif
   if ((hd->fn41.flags&1)==0 && (hd->fn41.bx)==(unsigned short)0xAA55) {
      geom->EDD_flags = hd->fn41.cx;
      geom->EDD_rev = hd->fn41.ah;
   }
   
   if (((geom->EDD_flags) & EDD_SUBSET) || buf.s5.version >= 6) {
      edd_t *dp;

      dp = (edd_t*)hdp[drive-0x80 + 1];
#ifdef DEBUG_PROBE
	printf("get_geom:  EDD  dp = %08X\n", (int)dp);
	fflush(stdout);
#endif
    /* update the pointer to the next drive */
      hdp[drive-0x80 + 1] = (void*)dp + sizeof(edd_t);

      /* regs.eax = 0x4800;		*/
      /* regs.edx = drive;		*/
      
#ifdef DEBUG_PROBE
	printf("get_geom: int13, fn=48\n");
	fflush(stdout);
#endif

	if ((dp->reg.flags&1) == 0 && dp->reg.ah == 0) {

	      if ((dp->info) & EDD_PARAM_GEOM_VALID) {
	         if ((geom->n_sect != dp->sectors || geom->n_head != dp->heads) &&
				((verbose>0 && !lba32) || verbose>=4) && 
				!(warned[drive-0x80]&1) ) {
	                warn("Int 0x13 function 8 and function 0x48 return different\n"
                	               "head/sector geometries for BIOS drive 0x%02X", drive);
        	        show_geom("fn 08", geom->n_cyl, geom->n_head, geom->n_sect);
	                show_geom("fn 48", dp->cylinders, dp->heads, dp->sectors);
			warned[drive-0x80] |= 1;
		    }

	/* prefer to return the fn 8 geometry */
#if 0
	         geom->n_cyl  = dp->cylinders;
	         geom->n_head = dp->heads;
	         geom->n_sect = dp->sectors;
#endif
		 total = dp->sectors;
		 total *= dp->heads;
		 total *= dp->cylinders;
		 if (total > geom->n_total_blocks) geom->n_total_blocks = total;
	
	      }
	      if (dp->total_sectors > geom->n_total_blocks)
			geom->n_total_blocks = dp->total_sectors;
	}
    }
    if (!(warned[drive-0x80]&4)) {
       if (hd_err) warn("LILO is compensating for a BIOS bug: (drive 0x%02X) heads > 255",
                           drive);
       if (sec_err) {
           warn("LILO will try to compensate for a BIOS bug: (drive 0x%02X) sectors > 63",
                           drive);
           if ((geom->EDD_flags & EDD_PACKET) && !lba32)
               die("LBA32 addressing should be used, not %s", linear ? "LINEAR" : "GEOMETRIC");
           if (!(geom->EDD_flags & EDD_PACKET)   &&   !(lba32 | linear) )
               warn("Drive 0x%02X may not be usable at boot-time.", drive);
       }
       warned[drive-0x80] |= 4;
    }
   
   return 0;
}


/* get the conventional memory size in Kb */
static int get_conv_mem(void)
{
#if 0
    if(fetch()) {
        printf("No memory information is available.\n\n");
        exit(0);
    }
#else
    if (notice(4)) exit(0);
#endif
    return (int)eq->mem;
}


/* print the conventional memory size */
static void do_ebda(void)
{
    int m, n, init;
    static char EBDA[]="Extended BIOS Data Area (EBDA)";
    
    m = get_conv_mem() - EBDA_EXTRA;
#if EBDA_EXTRA
    printf("*** BUGFIX - reported EBDA is increased by %dK - BUGFIX ***\n",
    	EBDA_EXTRA);
#endif
    if (m==640) printf("    no %s\n", EBDA);
    else printf("    %s = %dK\n", EBDA, 640-m);
    printf("    Conventional Memory = %dK    0x%06X\n", m, m<<10);
    m <<= 10;
    m -= 0x200;
    n = (select_loader()->size + SECTOR_SIZE - 1) / SECTOR_SIZE;
    n = m - (n+4+MAX_DESCR_SECS+(COMMAND_LINE_SIZE>256))*SECTOR_SIZE;
    init = (n - (MAX_SETUPSECS+1)*SECTOR_SIZE)>>4;
    if (init > DEF_INITSEG) init = DEF_INITSEG;
    printf("\n");

    printf("    The First stage loader boots at:  0x%08X  (0000:%04X)\n",
    			FIRSTSEG<<4, FIRSTSEG<<4);
    printf("    The Second stage loader runs at:  0x%08X  (%04X:%04X)\n",
    			n, n>>4, n&15);
    printf("    The kernel cmdline is passed at:  0x%08X  (%04X:%04X)\n",
    			m, init, m-(init<<4));

}

static char *number(unsigned int n)
{
    unsigned int k = 1000000000UL;	/* 10^9 */
    static char s[16];
    char *cp = s;
    
    while (n<k && k>1) k /= 1000UL;
    sprintf(cp,"%u",n/k);
    n %= k;
    k /= 1000UL;
    while (k) {
	while (*++cp) ;
	sprintf(cp,",%03u",n/k);
	n %= k;
	k /= 1000UL;
    }
    return s;
}


/* print the CHS geometry information for the specified disk */
static void print_geom(int dr, struct disk_geom geom)
{
    char ch_ser[24] = { 0 };
    char *sz = "KMGT";
    char *sp = sz;
    unsigned int n, m=0;

#ifdef DEBUG_PROBE
    if (!dr) geom.n_total_blocks = 4000000000UL;	/* 2.09Tb */
#endif

    if (geom.serial_no) sprintf(ch_ser, "vol-ID: %08X", geom.serial_no);
    printf("    bios=0x%02x, cylinders=%d, heads=%d, sectors=%d\t%s\n", 
	dr, geom.n_cyl, geom.n_head, geom.n_sect, ch_ser);
    n = geom.n_total_blocks/2;
    while (n > 999999) { n/=1000UL; n*=1024UL; n/=1000UL; sp++; }
    if (n > 999) {
	m = (n%1000UL)/10;
	n /= 1000UL;
	sp++;
    }
    if (m) printf("\t(%3u.%02u%cb", n, m, *sp);
    else printf("\t(%3u%cb", n, *sp);
    
    printf("%14s sectors)", number(geom.n_total_blocks));
    if (geom.EDD_flags & EDD_PACKET) {
/*	printf("\tEDD packet calls allowed");	*/
	printf("\tLBA32 supported (EDD bios)");
    } else printf("\tC:H:S supported (PC bios)");
    printf("\n");
}


/* print disk drive geometry for all drives */
static void do_geom_all(void)
{
   int d, hd, dr;
   struct disk_geom geom;
   
   for (hd=0; hd<0x81; hd+=0x80)
   for (d=0; d<16; d++) {
      dr = d+hd;
      if (get_geom(dr, &geom)==0) {
         if (dr==0x80) printf("\nBIOS reports %d hard drive%s\n", (int) geom.n_disks,
                                      (int)geom.n_disks==1 ? "" : "s");
      	 print_geom(dr, geom);
      }
   }
}


/* print disk drive geometry information for a particular drive */
static void do_geom(char *bios)
{
    int dr;
    struct disk_geom geom;

    dr = to_number(bios);
    if (get_geom(dr, &geom)==0) print_geom(dr, geom);
    else printf("Unrecognized BIOS device code 0x%02x\n", dr);
    
}


/* print an individual partition table entry */
static void print_pt(int index, struct partition pt)
{
    char bt[4], *ty, start[32], end[32], type[8];
    char x;
    int i;
    
    for (x=i=0; i<sizeof(pt); i++) x |= ((char*)&pt)[i];
    if (!x) {
    	printf("%4d\t\t\t     ** empty **\n", index);
    	return;
    }
    strcpy(bt,"   ");
    sprintf(type, "0x%02x", (int)pt.sys_ind);
    sprintf(start, "%4d:%d:%d",
    	(int)pt.cyl+((pt.sector&0xC0)<<2),
    	(int)pt.head,
    	(int)pt.sector & 0x3f );
    sprintf(end, "%4d:%d:%d",
    	(int)pt.end_cyl+((pt.end_sector&0xC0)<<2),
    	(int)pt.end_head,
    	(int)pt.end_sector & 0x3f );
    ty = type;
    if (pt.boot_ind==0x80) bt[1]='*';
    else if (pt.boot_ind==0) ; /* do nothing */
    else {
    	sprintf(bt+1,"%02x", (int)pt.boot_ind);
    }
    for (i=0; ptab[i].name; i++) {
	if (ptab[i].type == pt.sys_ind) {
	    ty = ptab[i].name;
	    break;
	} else if ((ptab[i].type|ptab[i].hide) == pt.sys_ind) {
	    bt[0] = 'H';
	    ty = ptab[i].name;
	    break;
	}
    }
    printf("%4d%18s%5s%11s%14s%12u%12u\n", index, ty, bt,
    	start, end, pt.start_sect, pt.nr_sects);
}


/* partition table display */
static void do_table(char *part)
{
    struct partition pt [PART_MAX_MAX+1];
    int volid;
    long long where[PART_MAX_MAX+1];
    int i,j;
    int extd = (extended_pt || verbose>0);
    
    j = read_partitions(part, extd ? nelem(pt)-1 : 0, &volid, pt, verbose>=5 ? where : NULL);
    extd |= j>PART_MAX;
    printf(" vol-ID: %08X\n\n%s\n", (int)volid, phead);
    for (i=0; i<PART_MAX; i++) {
	print_pt(i+1, pt[i]);
    }
    i=4;
    if (extd)
    while (pt[i].sys_ind) {
	print_pt(i+1, pt[i]);
	i++;
    }
    if (verbose>=5) {
    	printf("\n");
    	for (i=0; i<j; i++) printf("%4d%20lld%12d\n", i+1, where[i], (int)(where[i]/SECTOR_SIZE));
    }
}


/* list partition change-rules */
static void do_cr_pr(void)
{
    CHANGE_RULE *cr;
    
    cr = change_rules;
    printf("\t\tType Normal Hidden\n");
    if (!cr) printf("\t **** no change-rules defined ****\n");
    while (cr) {
	printf ("%20s  0x%02x  0x%02x\n", cr->type, (int)cr->normal, (int)cr->hidden);
	cr = cr->next;
    }
}

static int egamem;
static int mode, col, row, page;
/*
enum {VIDEO_UNKNOWN, VIDEO_MDA, VIDEO_CGA, VIDEO_EGA, VIDEO_MCGA,
	VIDEO_VGA, VIDEO_VESA, VIDEO_VESA_800};
 */

int get_video(void)	/* return -1 on error, or adapter type [0..7] */
{
    int adapter = 0;    /* 0=unknown, 1=MDA,HGC, 2=CGA, 3=EGA, 4=MCGA, 5=VGA,
		    			 6=VESA (640), 7=VESA (800) */
    int okay = 1;
    int monitor;
        
    if(fetch()) return -1;

    if ((okay=buf.s5.vid)) {
    /* get current video mode */
    /* reg.eax = 0x0F00;		*/
	if (verbose >= 6)
	    printf("get video mode\n");
	mode = v1->vid0F.al;
	col = v1->vid0F.ah;
	page = v1->vid0F.bh;
	row = v1->vid0F.bl + 1;
	if (mode==7) {
	    adapter=1;
	    row = 25;
	    okay = 0;
	} else if (col<80) {
	    adapter=2;
	    okay=0;
	} else adapter=2;	/* at least CGA */
    }
    if (okay>=2) {
    /* determine video adapter type */
    /*    reg.eax = 0x1200;	  call valid on EGA/VGA */
    /*    reg.ebx = 0xFF10;				*/
	if (verbose >= 6)
	    printf("determine adapter type\n");
	if ((unsigned)(monitor = v2->vid12.bh) <= 1U)  {
    	    adapter = 3; /* at least EGA */
	    egamem = v2->vid12.bl;
	}
	else {
	    okay = 0;
	}
    }
    if (okay>=2) {
	/* check for VGA */
    	/* reg.eax = 0x1A00;	   get display combination */
    	if (verbose >= 6)
	    printf("get display combination\n");
	if ( v2->vid1A.al==0x1A ) {
    	    monitor = (v2->vid1A.bx >> ((verbose>=9)*8) ) & 0xFF;
    	    switch (monitor) {
    	      case 1:
    	        adapter = 1;
    	        break;
    	      case 2:
    	        adapter = 2;
    	        break;
	      case 7:
	      case 8:
	        adapter = 5;	/* VGA */
    	        break;
    	      case 0xA:
    	      case 0xB:
    	      case 0xC:
    	        adapter = 4;	/* MCGA */
    	        break;
    	      default:
    	        okay = 0;
    	        break;
    	    }
    	} else {
    	    okay = 0;
    	}
    }
    if (okay>=3 && adapter==5) {
	/* check for BIOS bug (trashing DX) */
    	if (v25 && verbose >= 6)
	    printf("check Enable Screen Refresh\n");
	if (v25) {
	    video_36_bug = 2;	/* mark implemented */
	    
	    if ((v25->vid36.ax & 0xFF) != 0x12)  video_36_bug = 1;
	    else {
		if (v25->vid36.cx != 0x1234 || v25->vid36.bp != 0x4321)
		    video_36_bug |= 4;
		if (v25->vid36.dx != 0x5680) video_36_bug |= 8;
	    }
	}
	
	/* check for VESA extensions */
    	if (verbose >= 6)
	    printf("check VESA present\n");
	    
	if ((v3->vid4F00.ax == 0x4f) && strncmp("VESA", v3->vid4F00.sig, 4)==0)  adapter++;
	
	if (adapter > 5) {
	    /* reg.eax = 0x4f01;
	       reg.ecx = 0x0101;	   640x480x256 */
	    if ((v3->vid101.ax == 0x4f) && (v3->vid101.bits & 0x19) == 0x19) adapter ++;
	    else adapter--;
	}
	if (adapter > 6) {
	    /* reg.eax = 0x4f01;
	       reg.ecx = 0x0103;	   800x600x256 */
	    if ((v3->vid103.ax == 0x4f) && (v3->vid103.bits & 0x19) == 0x19) ;
	    else adapter--;
	}
    }
    if (verbose>=2)
    	printf ("mode = 0x%02x,  columns = %d,  rows = %d,  page = %d\n",
    		       mode, col, row, page);
    
    return adapter;
}

/* print VGA/VESA mode information */
void do_video(void)
{
static char *display[] = { "unknown", "MDA", "CGA", "EGA", 
		"MCGA", "VGA", "VGA/VESA", "VGA/VESA" };
    int adapter; /* 0=unknown, 1=MDA,HGC, 2=CGA, 3=EGA, 4=MCGA, 5=VGA,
    			 6=VESA (640), 7=VESA (800) */

    if (notice(4)) exit(0);
    
    adapter = get_video();
#if 0
    if(adapter<0) {
        printf("No video mode information is available.\n");
        return;
    }
#endif
    printf("%s adapter:\n\n", display[adapter]);
    if (adapter < 3 || (adapter == 3 && egamem < 1) ) {
        printf("No graphic modes are supported\n");
    } else {
	if (adapter != 4)
	    printf("    640x350x16    mode 0x0010\n");
	if (adapter >= 5) {
	    printf("    640x480x16    mode 0x0012\n\n");
	    printf("    320x200x256   mode 0x0013\n");
	}
	if (adapter >= 6)
	    printf("    640x480x256   mode 0x0101\n");
	if (adapter >= 7)
	    printf("    800x600x256   mode 0x0103\n");
    }
    if (video_36_bug && (verbose>0 || (video_36_bug&(8+4)))) {
     /* setting video_36_bug is a side effect of get_video */
	printf("\nEnable Screen Refresh %s.\n",
	    (video_36_bug & 4) ? "bugs are present" :
	    (video_36_bug & 8) ? "bug is present" :
	    (video_36_bug == 1) ? "is not supported" : "is supported");
    }
}

/* entry from lilo.c for the '-T' (tell) switch */
void probe_tell (char *cmd)
{
    struct Probes *pr = list;
    int n;
    char *arg;
    
    if (!(verbose>0)) printf("\n");
    for (; pr->cmd; pr++) {
	n = strlen(pr->cmd);
	arg = NULL;
	if (pr->cmd[n-1] == '=') arg = cmd+n;
	if (!strncasecmp(cmd, pr->cmd, n)) {
	    pr->prc(arg);
	    printf("\n");
	    exit(0);
	}
    }
    printf("Unrecognized option to '-T' flag\n");
    do_help();
    printf("\n");
    exit(1);
}


int bios_max_devs(void)
{
    struct disk_geom geom;
    int i;
    
    if (!fetch() && !get_geom(0x80, &geom)) {
	i = (buf.s5.disk & 0x7f) + 1;
	if (geom.n_disks == i) return i;
    }
    return BIOS_MAX_DEVS;    
}

#ifdef DEBUG_PROBE
static void dump_pt(unsigned char *pt)
{
    int i, j;
    for (j=0; j<4; j++) {
	for (i=0; i<16; i++) {
	    printf(" %02X", (int)(*pt++));
	}
	printf("\n");
    }
    printf("\n");
}
#endif

/* 
 *  return the bios device code of the disk, based on the geometry
 * 	match with the probe data
 *   side effect is to place the device code in geo->device
 * return -1 if indeterminate
 */
int bios_device(GEOMETRY *geo, int device)
{
    int bios1, bios, match, fd;
    int bios2, snmatch;
    int mbios[BD_MAX_HARD];
    struct disk_geom bdata;
    DEVICE dev;
    unsigned char part[PART_TABLE_SIZE];
    unsigned char extra[8];
    int serial;
    
        
    if (fetch()) return -1;
    
    if (verbose>=5) printf("bios_dev:  device %04X\n", device);
#ifdef DEBUG_PROBE
	fflush(stdout);
#endif    
    if (!has_partitions(device)) return -1;
        
    match = 0;
    bios1 = -1;		/* signal error */
    for (bios=0x80; bios<=buf.s5.disk; bios++) {
	mbios[bios-0x80] = 0;
	if (get_geom(bios, &bdata)) break;
	if (geo->cylinders == bdata.n_cyl &&
	    geo->heads == bdata.n_head &&
	    geo->sectors == bdata.n_sect) {
	    	match++;
	    	mbios[bios-0x80] = bios1 = bios;
	}
    }
    if (match == 1) {
    	if (verbose>=5) printf("bios_dev: match on geometry alone (0x%02X)\n",
    		bios1);
	return (geo->device = bios1);
    }

    device &= D_MASK(device);	/* mask to primary device */
    fd = dev_open(&dev,device,O_RDONLY);
    if (verbose>=5) printf("bios_dev:  masked device %04X, which is %s\n", 
    			device, dev.name);
    if (lseek(fd, PART_TABLE_OFFSET-8, SEEK_SET)!=PART_TABLE_OFFSET-8)
	die("bios_device: seek to partition table - 8");
    if (read(fd,extra,sizeof(extra))!= sizeof(extra))
	die("bios_device: read partition table - 8");
    serial = *(int*)(extra+2);
    if (lseek(fd, PART_TABLE_OFFSET, SEEK_SET)!=PART_TABLE_OFFSET)
	die("bios_device: seek to partition table");
    if (read(fd,part,sizeof(part))!= sizeof(part))
	die("bios_device: read partition table");
    dev_close(&dev);

#ifdef DEBUG_PROBE
    if (verbose>=5) {
        printf("serial number = %08X\n", serial);
        dump_pt(part);
    }
#endif

    if (verbose>=5) printf("bios_dev: geometry check found %d matches\n", match);
    
    snmatch = match = 0;
    bios2 = bios1 = -1;

 /* 'bios' is set leaving the 'for' above */
    while (--bios >= 0x80) {
	get_geom(bios, &bdata);
	if (verbose>=5) {
		printf("bios_dev: (0x%02X)  vol-ID=%08X  *PT=%08lX\n",
			bios, bdata.serial_no, (long)bdata.pt);
#ifdef DEBUG_PROBE
		dump_pt((void*)bdata.pt);
#endif
	}
	if ( !memcmp(part,bdata.pt,sizeof(part)) ) {
	    match++;
	    bios1 = bios;
	}
	if ( bdata.serial_no && serial==bdata.serial_no ) {
	    snmatch++;
	    bios2 = bios;
	}
    }
    if (verbose>=5) printf("bios_dev: PT match found %d match%s (0x%02X)\n",
    		match, match==1 ? "" : "es", bios1&255);
    if (match != 1) {
	match = snmatch;
	bios1 = bios2;
	if (verbose>=5) printf("bios_dev: S/N match found %d match%s (0x%02X)\n",
    		match, match==1 ? "" : "es", bios1);
    }

    if (match == 1) {
	get_geom(bios1, &bdata);
	if (  (geo->sectors && geo->sectors!=bdata.n_sect)  ||
	       (geo->heads && geo->heads!=bdata.n_head)  )  {
	    unsigned int nblocks = geo->cylinders * geo->heads * geo->sectors;

	    if (!(lba32 | linear) && !(warned[bios1-0x80]&2) ) {
		warn("Kernel & BIOS return differing head/sector geometries for device 0x%02X", bios1);
		show_geom("Kernel", geo->cylinders, geo->heads, geo->sectors);
		show_geom("  BIOS", bdata.n_cyl, bdata.n_head, bdata.n_sect);
		warned[bios1-0x80] |= 2;
	    }
#if 1
	    geo->sectors = bdata.n_sect;
	    geo->heads = bdata.n_head;
	    if (bdata.n_total_blocks > nblocks) nblocks = bdata.n_total_blocks;
	    geo->cylinders = nblocks / (bdata.n_head*bdata.n_sect);
#endif
	}
	return (geo->device = bios1);
    }

    return -1;
}


#if BITMAP
static void do_bitmap(char *file)
{
    printf("Color, Positioning, and Timer information for file:  %s\n", file);
    printf("...<unimplemented>...\n");
}
#endif

static unsigned char dl,dh;

static int get_bios(void)
{
    if (fetch() || buf.s5.version<5) return -1;
#if BETA_TEST
	if (verbose>=5) printf("get_bios 1\n");
#endif
    dl = eq->boot_dx;
#if BETA_TEST
	if (verbose>=5) printf("get_bios 2\n");
#endif
    dh = eq->boot_dx >> 8;
    
    return eq->boot_dx;
}


void check_bios(void)
{
#if BETA_TEST
	if (verbose>=5) printf("check_bios 1\n");
#endif
    if (bios_passes_dl == DL_NOT_SET) {
	bios_passes_dl = DL_UNKNOWN;
	
	if (get_bios() < 0) return;
#if BETA_TEST
	if (verbose>=5) printf("check_bios 2\n");
#endif
	if (dl==0xFE) {
	    if ( !((dh>=0x80 && dh<=DEV_MASK) || dh==0) )
		bios_passes_dl = DL_BAD;
	}
	else if ( dl>=0x80 && dl<=DEV_MASK ) bios_passes_dl = DL_MAYBE;
	else if ( dl > 0 ) bios_passes_dl = DL_BAD;
    }
    /* already set, leave alone */
#if BETA_TEST
	if (verbose>=5) printf("check_bios 3  bios_passes_dl=%d\n", (int)bios_passes_dl);
#endif
}


void do_bios(void)
{
    int code=1;
    
static char *ord[] =
{ "first", "second", "3rd", "4th", "5th", "6th", "7th", "8th",
  "9th", "10th", "11th", "12th", "13th", "14th", "15th", "16th" };
    
    notice(5);
    if (get_bios() < 0)
	printf("No information available on the state of DL at boot.\n");
    else
    {
	printf("BIOS provided boot device is 0x%02x  (DX=0x%04X).\n",
		code=(dl==0xFE ? dh : dl), eq->boot_dx);
	bios_passes_dl = DL_NOT_SET;
	check_bios();
    }
    printf("\nUnless overridden, 'bios-passes-dl = %s' will be assumed.",
	bios_passes_dl == DL_BAD ? "no" :
	bios_passes_dl == DL_MAYBE ? "maybe" :
	bios_passes_dl == DL_GOOD ? "yes" : "unknown" );
    if (bios_passes_dl > DL_BAD) {
	char *cp = NULL;
	char *cn = NULL;

	if (code>=0 && code<2) { cp="floppy"; cn=ord[code]; }
	if (code>=0x80 && code<=0x8f) { cp="hard"; cn=ord[code&15]; }
	if (cp)
	printf("  If you\nactually booted from the %s %s drive, then this assumption is okay.",
		cn, cp);
#if 0
	if (bios_passes_dl == DL_MAYBE)
	    printf("\nIf the BIOS always gets DL set correctly, you might consider specifying\n"
	           "  'bios_passes_dl = yes' or '-Z1'.\n");
#endif
    }
    printf("\n");
}

#if VOLID
static void do_volid(void)
{
    int bios, n, i, k, sv, nv, unique;
    struct disk_geom geom;
    unsigned int serial[MAX_BIOS_DEVICES];
    int uniq[MAX_BIOS_DEVICES], valid[MAX_BIOS_DEVICES];

    if (notice(4)) exit(0);
    
    printf("\n  BIOS     Volume ID\n\n");
    unique = 1;
    nv = n = 0;
    for (bios=0x80; bios<0x80+MAX_BIOS_DEVICES && !get_geom(bios, &geom); bios++) {
	int uq = 1;
	i = bios - 0x80;
#if 0
	if (i==0 || i==2) geom.serial_no = 0;
	if (i==4) geom.serial_no = serial[2];
#endif

	serial[i] = geom.serial_no;
	valid[i] = sv = serial_valid(geom.serial_no, bios);
	nv |= !sv;
	if (sv) for (k=0; k<i; k++) uq &= (geom.serial_no != serial[k]);
	uniq[i] = uq;
	unique &= uq;
	n++;

	printf("  0x%02X     %08X %s%s\n", i+0x80, serial[i],
		uq ? "" : "*", sv ? "" : "-");
    }

    printf("\nVolume ID's are%s unique.\n", unique ? " all" : " NOT");
    if (nv)
	printf("   '-' marks an invalid Volume ID which will be automatically updated\n"
		"\tthe next time  /sbin/lilo  is executed.\n");
    if (!unique)
	printf("   '*' marks a volume ID which is duplicated.  Duplicated ID's must be\n"
		"\tresolved before installing a new boot loader.  The volume ID may\n"
		"\tbe cleared using the '-z' and '-M' switches.\n"
		);
    printf("\n");
}
#endif

