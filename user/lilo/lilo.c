/* lilo.c  -  LILO command-line parameter processing */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2006 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <dirent.h>
/*#include <asm/page.h>*/

#include "config.h"
#include "lilo.h"
#include "common.h"
#include "cfg.h"

#if !__MSDOS__
#include "raid.h"
#include "boot.h"
#include "device.h"
#include "flags.i"
#include "geometry.h"
#endif /* !__MSDOS__ */
#include "map.h"
#if !__MSDOS__
#include "bsect.h"
#include "identify.h"
#include "partition.h"
#include "probe.h"
#include "temp.h"
#include "loader.h"
#include "md-int.h"
#include "edit.h"
#endif /* !__MSDOS__ */


char *config_file;		/* actual name of the config file */
int config_read;		/* readable by other than root */
FILE *errstd;

static void configuration(void)
{
#if VERSION_MINOR>=50 && !__MSDOS__
{
		printf(
		"-DBOOT_PARAMS_1=%d -DBOOT_PARAMS_2=%d  PATH_MAX=%d"
		  "\n"
		  ,
		  (int)sizeof(BOOT_PARAMS_1),
		  (int)sizeof(BOOT_PARAMS_2),
		  PATH_MAX
		     );
}
{
#include "bitmap.h"
	RGB pal[16];
	RGB2 pal2[16];
	
	printf("\nBMFH=%d BMH=%d BMH2=%d RGB=%d(%d) RGB2=%d(%d) LH=%d\n",
	(int)sizeof(BITMAPFILEHEADER),
	(int)sizeof(BITMAPHEADER),
	(int)sizeof(BITMAPHEADER2),
	(int)sizeof(RGB),
	(int)sizeof(pal),
	(int)sizeof(RGB2),
	(int)sizeof(pal2),
	(int)sizeof(BITMAPLILOHEADER) );
	printf("\nBPB=%d BP_DOS=%d\n",
		(int)sizeof(BIOS_PARAMETER_BLOCK),
		(int)sizeof(BOOT_PARAMS_DOS)
		  );
}
#ifdef LCF_FIRST6
	printf("\nSECTOR_ADDR6=%d\n", (int)sizeof(SECTOR_ADDR6));
#endif

#endif /* VERSION_MINOR>=50 && !__MSDOS__ */

#if !__MSDOS__
{
  unsigned int j;
  if (verbose>=5) {
    if (crc(First.data,First.size)) {
	j = crc(First.data,First.size-4);
	brev(j);
	printf("1=0x%x\n", j);
    }
    if (crc(Second.data,Second.size)) {
	j = crc(Second.data,Second.size-4);
	brev(j);
	printf("2=0x%x\n", j);
    }
    if (crc(Third.data,Third.size)) {
	j = crc(Third.data,Third.size-4);
	brev(j);
	printf("3=0x%x\n", j);
    }
    if (crc(Bitmap.data,Bitmap.size)) {
	j = crc(Bitmap.data,Bitmap.size-4);
	brev(j);
	printf("B=0x%x\n", j);
    }
    if (crc(Chain.data,Chain.size)) {
	j = crc(Chain.data,Chain.size-4);
	brev(j);
	printf("C=0x%x\n", j);
    }
    if (crc(Mbr.data,Mbr.size)) {
	j = crc(Mbr.data,Mbr.size-4);
	brev(j);
	printf("M=0x%x\n", j);
    }
    if (crc(Mbr2.data,Mbr2.size)) {
	j = crc(Mbr2.data,Mbr2.size-4);
	brev(j);
	printf("N=0x%x\n\n", j);
    }
  }
}

#if BETA_TEST
{
    int i, j, k=0;
extern int has_partitions_beta(dev_t dev);	/* defined in geometry.c */


    printf("\n");
    for (i=0; i<256; i++) {
	if ( has_partitions_beta(MKDEV(i,0)) != has_partitions(MKDEV(i,0)) ) {
	    printf("Major device = %d is not configured.\n", i);
	    k ++;
	}
    }
    printf("%sk = %d (should be 0)\n\n", k?"ERROR: ":"", k);
    for (i=0, j=0; i<40960; i+=17) {
        dev_t dev;
        int major, minor;
        for (k=0; k<81920; k+=19) {
            dev = MKDEV(i,k);
            major = MAJOR(dev);
            minor = MINOR(dev);
            if (major != i  ||  minor != k) {
                printf("ERROR: (%d,%d) -> (%d,%d)\n",
                    i, k, major, minor);
                j++;
            }
        }
    }
    if (j==0) printf("MKDEV check passed\n");
}
#endif

#if VERSION_MINOR>=50
{
	dev_t dev; int i;
	BOOT_VOLID x;
	BOOT_SECTOR b;
	dev = 0xFFF0;
	i = dev;
	printf("dev_t is %ssigned size=%d  i=%08X\n", i==0xFFF0 ? "un" : "", (int)sizeof(dev_t), i);
	printf("size of BOOT_VOLID = %d   BOOT_SECTOR = %d\n", (int)sizeof(x), (int)sizeof(b));
	printf("Size of MENUTABLE = %d\n", (int)sizeof(MENUTABLE));
}
#endif
		printf("\nCFLAGS = " CFLAGS "\n");
#if defined(LCF_DEVMAPPER) && defined(HAS_LIBDEVMAPPER_H)
                printf("With");
#else
                printf("Without");
#endif
                printf(" device-mapper\n");
		printf("\nglibc version %d.%d\n", __GLIBC__, __GLIBC_MINOR__);
		printf("Kernel Headers included from  %d.%d.%d\n",
			LINUX_VERSION_CODE>>16,
			LINUX_VERSION_CODE>>8 & 255,
			LINUX_VERSION_CODE & 255);
		printf("Maximum Major Device = %d\n", MAJOR(~0UL));
#endif /* !__MSDOS__ */
		printf("MAX_IMAGES = %d\t\tc=%d, s=%d, i=%d, "
				"l=%d, ll=%d, f=%d, d=%d, ld=%d\n",
			MAX_IMAGES, (int)sizeof(char),
			(int)sizeof(short), (int)sizeof(int),
			(int)sizeof(long), (int)sizeof(
#if !__MSDOS__
			long
#endif /* !__MSDOS__ */
 			     long),
			(int)sizeof(float), (int)sizeof(double),
			(int)sizeof(long double)
			);
		printf("IMAGE_DESCR = %d   DESCR_SECTORS = %d\n\n",
			(int)sizeof(IMAGE_DESCR), (int)sizeof(DESCR_SECTORS));
}

#if !__MSDOS__

static void show_other(int fd)
{
    BOOT_SECTOR buf[SETUPSECS-1];
    const unsigned char *drvmap;
    const unsigned char *prtmap;

    if (read(fd,buf,sizeof(buf)) != sizeof(buf))
	die("Read on map file failed (access conflict ?) 1");
    if (!strncmp(buf[0].par_c.signature-4,"LILO",4)) {
	printf("    Pre-21 signature (0x%02x,0x%02x,0x%02x,0x%02x)\n",
	  buf[0].par_c.signature[0],buf[0].par_c.signature[1],
	  buf[0].par_c.signature[2],buf[0].par_c.signature[3]);
	return;
    }
    if (strncmp(buf[0].par_c.signature,"LILO",4)) {
	printf("    Bad signature (0x%02x,0x%02x,0x%02x,0x%02x)\n",
	  buf[0].par_c.signature[0],buf[0].par_c.signature[1],
	  buf[0].par_c.signature[2],buf[0].par_c.signature[3]);
	return;
    }
    drvmap = ((unsigned char *) buf+buf[0].par_c.drvmap);
    prtmap = drvmap+2*(DRVMAP_SIZE+1);
    while (drvmap[0] && drvmap[1]) {
	if (drvmap[0]==0xFF && drvmap[1]==0xFF) {
	    if (drvmap[3]==0xFF) printf("    Master-Boot:  This BIOS drive will always appear as 0x80 (or 0x00)\n");
	    else printf("    Boot-As:  This BIOS drive will always appear as 0x%02X\n", drvmap[3]);
	    drvmap += 4;
	} else {
	    printf("    BIOS drive 0x%02X is mapped to 0x%02X\n",drvmap[0],
						drvmap[1]);
	    drvmap += 2;
	}
    }
    /* fix VERY old bug -- offset of 0 in PT is okay */
    while (prtmap[0] /*** && prtmap[1] ***/ ) {
	printf("    BIOS drive 0x%02x, offset 0x%x: 0x%02x -> 0x%02x\n",
	  prtmap[0],prtmap[1]+PART_TABLE_OFFSET,prtmap[2],prtmap[3]);
	prtmap += 4;
    }
}
#endif /* !__MSDOS__ */

static void show_images(char *map_file)
{
#if !__MSDOS__
    DESCR_SECTORS descrs;
    BOOT_SECTOR boot;
    MENUTABLE menu;
    BOOT_PARAMS_2 param2;
    GEOMETRY geo;
    SECTOR_ADDR addr[4];
    char buffer[SECTOR_SIZE];
#else /* __MSDOS */
static DESCR_SECTORS descrs;
static char buffer[SECTOR_SIZE];
#endif /*__MSDOS__ */
    char *name;
    int fd,image;
    int tsecs;
    int tlinear, tlba32;
    unsigned short flags;
    time_t Time;

#if !__MSDOS__
    fd = geo_open(&geo,map_file,O_RDONLY);
#else  /* __MSDOS__ */
    if ((fd = open(map_file,O_RDONLY))<=0)
	die("Cannot open map file: %s", map_file);
#endif /* __MSDOS__ */
    if (read(fd,buffer,SECTOR_SIZE) != SECTOR_SIZE)
	die("read cmdline %s: %s",map_file,strerror(errno));
    if (read(fd,(char*)&descrs,sizeof(descrs)) != sizeof(descrs))
	die("read descrs %s: %s",map_file,strerror(errno));
#if !__MSDOS__
    if (lseek(fd, SECTOR_SIZE, SEEK_CUR) <= 0)	/* skip zero sector */
	die("lseek over zero sector %s: %s",map_file,strerror(errno));
    if (read(fd,(char*)&param2,sizeof(param2)) != sizeof(param2))
	die("read second params %s: %s",map_file,strerror(errno));
    if (lseek(fd, - sizeof(menu), SEEK_END) <= 0)
	die("lseek keytable %s: %s",map_file,strerror(errno));
    if (read(fd,(char*)&menu,sizeof(menu)) != sizeof(menu))
	die("read keytable %s: %s",map_file,strerror(errno));
    tlba32  = (descrs.d.descr[0].start.device & LBA32_FLAG) != 0;
    tlinear = !tlba32 && (descrs.d.descr[0].start.device & LINEAR_FLAG);
    if (tlinear != linear  ||  tlba32 != lba32) {
        printf("Warning: mapfile created with %s option\n",
	       tlinear?"linear":tlba32?"lba32":"no linear/lba32");
        linear = tlinear;  lba32 = tlba32;
    }
    if (verbose) {
	bsect_read(cfg_get_strg(cf_options,"boot"),&boot);
#if 1
	if (boot.par_1.cli != 0xFA) {	/* relocation happened */
	    int len, offset=0;
	    if (boot.sector[0] == 0xEB)		/* jmp short */
		offset = boot.sector[1]+2;
	    else if (boot.sector[0] == 0xE9)	/* jmp near */
		offset = *(short*)&boot.sector[1] + 3;
	    else die("Cannot undo boot sector relocation.");
	    len = SECTOR_SIZE - offset;
	    memmove(&boot, &boot.sector[offset], len);
	    if (boot.par_1.cli != 0xFA)
		die("Cannot recognize boot sector.");
	}
#endif
#if 1
        Time = boot.par_1.map_stamp;
	printf("Installed:  %s\n", ctime(&Time));
#else
	printf("Installed:  %s\n", ctime((time_t*)&boot.par_1.map_stamp));
#endif
	printf("Global settings:\n");
	tsecs = (param2.delay*2197+3999)/4000;
	printf("  Delay before booting: %d.%d seconds\n",tsecs/10,tsecs % 10);
	if (param2.timeout == 0xffff) printf("  No command-line timeout\n");
	else {
	    tsecs = (param2.timeout*2197+3999)/4000;
	    printf("  Command-line timeout: %d.%d seconds\n",tsecs/10,
	      tsecs % 10);
	}
	printf("  %snattended booting\n", param2.flag2&FLAG2_UNATTENDED ? "U" : "No u");
	printf("  %sPC/AT keyboard hardware prescence check\n", param2.flag2&FLAG2_NOKBD ? "" : "No ");
	if (boot.par_1.prompt & FLAG_PROMPT) printf("  Always enter boot prompt\n");
	else printf("  Enter boot prompt only on demand\n");
	printf("  Boot-time BIOS data%s saved\n",
		boot.par_1.prompt & FLAG_NOBD ? " NOT" : "");
	printf("  Boot-time BIOS data auto-suppress write%s bypassed\n",
		boot.par_1.prompt & FLAG_BD_OKAY ? "" : " NOT");
	printf("  Large memory (>15M) is%s used to load initial ramdisk\n", 
		boot.par_1.prompt & FLAG_LARGEMEM ? "" : " NOT");
	printf("  %sRAID installation\n",
		boot.par_1.prompt & FLAG_RAID ? "" : "Non-");
	printf("  Boot device %s be used for the Map file\n",
		boot.par_1.prompt & FLAG_MAP_ON_BOOT ? "WILL" : "will not");
	if (!param2.port) printf("  Serial line access is disabled\n");
	else printf("  Boot prompt can be accessed from COM%d\n",
	      param2.port);
	if (!param2.msg_len) printf("  No message for boot prompt\n");
	else if (!cfg_get_strg(cf_options,"bitmap"))
	    printf("  Boot prompt message is %d bytes\n",param2.msg_len);
	else printf("  Bitmap file is %d paragraphs (%d bytes)\n",
			param2.msg_len, 16*param2.msg_len);
/* 22.6.2 begin */
	if (*(unsigned short *) buffer != DC_MAGIC /* || !buffer[2] */)
/* 22.6.2 end */
	    printf("  No default boot command line\n");
	else printf("  Default boot command line: \"%s\"\n",buffer+2);
	if (verbose>=3) {
	    printf("Serial numbers %08X\n", menu.serial_no[0]);
	}
	printf("Images:\n");
    }
/* 22.7 begin */
    else	/* verbose==0 */
#endif /* !__MSDOS__ */
    {
	if (*(unsigned short *) buffer == DC_MAGIC)
	    printf("Default boot command line: \"%s\"\n",buffer+2);
    }
/* 22.7 end */
    for (image = 0; image < MAX_IMAGES; image++) {
	if (*(name = descrs.d.descr[image].name)) {
#if __MSDOS__
	    printf("%s\n", name
#else /* !__MSDOS__ */
	    printf("%s%-" S(MAX_IMAGE_NAME) "s %s%s%s",verbose > 0 ? "  " : "",name,
	      image ? "" : "*",
#ifdef LCF_VIRTUAL
	      descrs.d.descr[image].flags & FLAG_VMDEFAULT ? "@" :
#endif
	      "",
#ifdef LCF_NOKEYBOARD
	      descrs.d.descr[image].flags & FLAG_NOKBDEFAULT ? "&" :
#endif
	      ""
#endif /* !__MSDOS__ */
	      );
#if !__MSDOS__
	    if (verbose >= 2) {
	        if (descrs.d.descr[image].start.device & (LINEAR_FLAG|LBA32_FLAG)) {
		   unsigned int sector;
		   sector = (descrs.d.descr[image].start.device & LBA32_FLAG)
		      && (descrs.d.descr[image].start.device & LBA32_NOCOUNT)
		        ? descrs.d.descr[image].start.num_sect : 0;
		   sector = (sector<<8)+descrs.d.descr[image].start.head;
	           sector = (sector<<8)+descrs.d.descr[image].start.track;
		   sector = (sector<<8)+descrs.d.descr[image].start.sector;
		   printf(" <dev=0x%02x,%s=%d>",
		     descrs.d.descr[image].start.device&DEV_MASK,
		     descrs.d.descr[image].start.device&LBA32_FLAG ? "lba32" : "linear",
		     sector);
		}
	        else { /*  CHS addressing */
		    printf(" <dev=0x%02x,hd=%d,cyl=%d,sct=%d>",
		      descrs.d.descr[image].start.device,
		      descrs.d.descr[image].start.head,
		      descrs.d.descr[image].start.track,
		      descrs.d.descr[image].start.sector);
		}
	    }
	    printf("\n");
	    if (verbose >= 1) {
		flags = descrs.d.descr[image].flags;
#ifdef LCF_VIRTUAL
		if (flags & FLAG_VMDISABLE)
		    printf("    Virtual Boot is disabled\n");
		if (flags & FLAG_VMWARN)
		    printf("    Warn on Virtual boot\n");
#endif		
#ifdef LCF_NOKEYBOARD
		if (flags & FLAG_NOKBDISABLE)
		    printf("    NoKeyboard Boot is disabled\n");
#endif		
		if ( !(flags & FLAG_PASSWORD) )
		    printf("    No password\n");
		else printf("    Password is required for %s\n",flags &
		      FLAG_RESTR ? "specifying options" : "booting this image");
		printf("    Boot command-line %s be locked\n",flags &
		  FLAG_LOCK ? "WILL" : "won't");
		printf("    %single-key activation\n",flags & FLAG_SINGLE ?
		  "S" : "No s");
		if (flags & FLAG_KERNEL) {
#ifdef NORMAL_VGA
		    if (!(flags & FLAG_VGA))
		       printf("    VGA mode is taken from boot image\n");
		    else {
			printf("    VGA mode: ");
			switch (descrs.d.descr[image].vga_mode) {
			    case NORMAL_VGA:
				printf("NORMAL\n");
				break;
			    case EXTENDED_VGA:
				printf("EXTENDED\n");
				break;
			    case ASK_VGA:
				printf("ASK\n");
				break;
			    default:
				printf("%d (0x%04x)\n",
				  descrs.d.descr[image].vga_mode,
				  descrs.d.descr[image].vga_mode);
			}
		    }
#endif
		    if (!(flags & FLAG_LOADHI))
			printf("    Kernel is loaded \"low\"\n");
		    else printf("    Kernel is loaded \"high\"\n");
		    if (!*(unsigned int *) descrs.d.descr[image].rd_size)
			printf("    No initial RAM disk\n");
		    else printf("    Initial RAM disk is %d bytes\n",
			  *(unsigned int *) descrs.d.descr[image].rd_size);
		    if (flags & FLAG_TOOBIG)
			printf("       and is too big to fit between 4M-15M\n");
		}
		if (!geo_find(&geo,descrs.d.descr[image].start)) {
		    printf("    Map sector not found\n");
		    continue;
		}
		if (read(fd,addr,4*sizeof(SECTOR_ADDR)) !=
		  4*sizeof(SECTOR_ADDR))
			die("Read on map file failed (access conflict ?) 2");
		if (!geo_find(&geo,addr[0]))
		    printf("    Fallback sector not found\n");
		else {
		    if (read(fd,buffer,SECTOR_SIZE) != SECTOR_SIZE)
			die("Read on map file failed (access conflict ?) 3");
		    if (*(unsigned short *) buffer != DC_MAGIC)
			printf("    No fallback\n");
		    else printf("    Fallback: \"%s\"\n",buffer+2);
		}
#define OTHER 0
#if OTHER
		if (flags & FLAG_KERNEL)
#endif
		    if (!geo_find(&geo,addr[1]))
			printf("    Options sector not found\n");
		    else {
			if (read(fd,buffer,SECTOR_SIZE) != SECTOR_SIZE)
			    die("Read on map file failed (access conflict ?) 4");
			if (*buffer) printf("    Options: \"%s\"\n",buffer);
			else printf("    No options\n");
		    }
#if OTHER
		else {
#else
		if (!(flags & FLAG_KERNEL)) {
#endif
		    if (geo_find(&geo,addr[3])) show_other(fd);
		    else printf("    Image data not found\n");
		}
	    }
#endif /*  !__MSDOS__ */
	} /* if */
    } /* for */
#undef OTHER
    (void) close(fd);
#if !__MSDOS__
    if (descrs.l.checksum ==
    	  crc32(descrs.sector, sizeof(descrs.l.sector), CRC_POLY1) )
#endif /* !__MSDOS__ */
    	  	exit(0);
#if !__MSDOS__
    fflush(stdout);
    fprintf(errstd,"Checksum error\n");
    exit(1);
#endif /* !__MSDOS__ */
}


static void usage(char *name)
{
    char *here;

#if !__MSDOS__
    here = strrchr(name,'/');
#else /* __MSDOS__ */
    here = strrchr(name,'\\');
#endif /* __MSDOS__ */
    if (here) name = here+1;
    fprintf(errstd,"usage: %s [ -C config_file ] -q [ -m map_file ] "
      "[ -v N | -v ... ]\n",name);
#if !__MSDOS__
    fprintf(errstd,"%7s%s [ -C config_file ] [ -b boot_device ] [ -c ] "
      "[ -g | -l | -L ]\n","",name);
    fprintf(errstd,"%12s[ -F ] [ -i boot_loader ] [ -m map_file ] [ -d delay ]\n","");
    fprintf(errstd,"%12s[ -v N | -v ... ] [ -t ] [ -s save_file | -S save_file ]\n",
      "");
    fprintf(errstd,"%12s[ -p ][ -P fix | -P ignore ] [ -r root_dir ] [ -w | -w+ ]\n","");
#endif /* !__MSDOS__ */
    fprintf(errstd,"%7s%s [ -C config_file ] [ -m map_file ] "
      "-R [ word ... ]\n","",name);
#if !__MSDOS__
    fprintf(errstd,"%7s%s [ -C config_file ] -I name [ options ]\n","",name);
    fprintf(errstd,"%7s%s [ -C config_file ] [ -s save_file ] "
      "-u | -U [ boot_device ]\n","",name);
    fprintf(errstd,"%7s%s -A /dev/XXX [ N ]\t\tinquire/activate a partition\n","",name);
    fprintf(errstd,"%7s%s -M /dev/XXX [ mbr | ext ]\tinstall master boot record\n","",name);
    fprintf(errstd,"%7s%s -T help \t\t\tlist additional options\n", "", name);
    fprintf(errstd,"%7s%s -X\t\t\t\tinternal compile-time options\n", "", name);
#endif /* !__MSDOS__ */
    fprintf(errstd,"%7s%s -V [ -v ]\t\t\tversion information\n\n","",name);
    exit(1);
}


int main(int argc,char **argv)
{
    char *name,*reboot_arg,*ident_opt,*new_root;
    char *tell_param, *uninst_dev, *param, *act1, *act2, ch;
static char *bitmap_file;
    int more,version,uninstall,validate,activate,instmbr,geom;
    int fd, temp=0, tell_early=0;
    int raid_offset;
#if !__MSDOS__
    struct stat st;
#endif /* !__MSDOS__ */

    errstd = stderr;
#if VERSION_MINOR>=50
    if (sizeof(MENUTABLE)!=256) die("MENUTABLE is not 256 bytes (common.h)");
#if !__MSDOS__
    cfg_alpha_check();
#endif /* !__MSDOS__ */
#endif
    config_file = DFL_CONFIG;
    act1 = act2 = tell_param = 
	    reboot_arg = identify = ident_opt = new_root = uninst_dev = NULL;
    do_md_install = zflag =
	    version = uninstall = validate = activate = instmbr = 0;
    verbose = -1;
#if !__MSDOS__
    name = *argv;
#else  /* __MSDOS__ */
    name = "lilo";
#endif /* __MSDOS__ */
    argc--;

#if !__MSDOS__    
    if (atexit( (void(*)(void)) sync)) die("atexit(sync)");
    if (atexit( (void(*)(void)) purge)) die("atexit(purge)");
#endif /* !__MSDOS__ */
    
    cfg_init(cf_options);
    while (argc && **++argv == '-') {
	argc--;
      /* first those options with a mandatory parameter */
      /* Notably absent are "RuUvw" */
	if (strchr("AbBCdDEfiImMPrsSTxZ", ch=(*argv)[1])) {
	    if ((*argv)[2]) param = (*argv)+2;
	    else {
		param = *++argv;
		if(argc-- <= 0) usage(name);
	    }
	} else { 
	    param = NULL;
	    if (strchr("cFglLpqtVXz", ch)	/* those with no args */
	    	&& (*argv)[2]) usage(name);
	}
#if 0
fprintf(errstd,"argc=%d, *argv=%s, ch=%c param=%s\n", argc, *argv, ch, param);
#endif
	switch (ch) {
#if !__MSDOS__
	    case 'A':
		activate = 1;
		act1 = param;
		if (argc && argv[1][0] != '-') {
		    act2 = *++argv;
		    argc--;
		}
		break;
	    case 'b':
		cfg_set(cf_options,"boot",param,NULL);
		break;
	    case 'B':
		cfg_set(cf_options,"bitmap",param,NULL);
		break;
	    case 'c':
		cfg_set(cf_options,"compact",NULL,NULL);
		compact = 1;
		break;
#endif /* !__MSDOS */
	    case 'C':
		config_file = param;
		break;
#if !__MSDOS__
	    case 'd':
		cfg_set(cf_options,"delay",param,NULL);
		break;
	    case 'D':
		cfg_set(cf_options,"default",param,NULL);
		break;
	    case 'E':
	        eflag=1;
	        bitmap_file = param;
	        break;
	    case 'f':
		cfg_set(cf_options,"disktab",param,NULL);
		break;
	    case 'F':
		force_fs=1;
		break;
	    case 'g':
		geometric |= AD_GEOMETRIC;
		break;
	    case 'H':
		force_raid=1;
		break;
	    case 'i':
		cfg_set(cf_options,"install",param,NULL);
		break;
	    case 'I':
		identify = param;
		if (argc && *argv[1] != '-') {
		    ident_opt = *++argv;
		    argc--;
		} else {
		    ident_opt = "i";
		}
		break;
	    case 'l':
		geometric |= AD_LINEAR;
		break;
	    case 'L':
		geometric |= AD_LBA32;
		break;
#endif /* !__MSDOS__ */
	    case 'm':
		cfg_set(cf_options,"map",param,NULL);
		break;
#if !__MSDOS__
	    case 'M':
		instmbr = 1;
		act1 = param;
#if !defined LCF_BUILTIN	|| 1
		if (argc && argv[1][0] != '-') {
		    act2 = *++argv;
		    argc--;
		}
#endif
		break;
	    case 'p':
		passw = 1;	/* force re-gen of password file */
		break;
	    case 'P':
		if ((act1=strchr(param,'='))) {
		    *act1++ = 0;	/* null terminate */
		    cfg_set(cf_options,param,act1,NULL);
		}
		else if (!strcasecmp(param,"fix"))
		    cfg_set(cf_options,"fix-table",NULL,NULL);
		else if (!strcasecmp(param,"ignore"))
		    cfg_set(cf_options,"ignore-table",NULL,NULL);
		else if (!strcasecmp(param,"x"))
		    extended_pt = 1;
		else
		    cfg_set(cf_options,param,NULL,NULL);
		break;
#endif /* !__MSDOS__ */
	    case 'q':
		query = 1;
		break;
#if !__MSDOS__
	    case 'r':
		new_root = param;
		break;
#endif /* !__MSDOS__ */
	    case 'R':
	        if (*(param = (*argv)+2)) argc++;
	        else if (argc) param = *++argv;
	        else reboot_arg = "";
	        
		while (argc) {
			if (!reboot_arg)
			    *(reboot_arg = alloc(strlen(param)+1)) = 0;
			else {
			    param = *++argv;
			    strcat(reboot_arg = ralloc(reboot_arg,
			        strlen(reboot_arg)+strlen(param)+2)," ");
			}
			strcat(reboot_arg, param);
			argc--;
		    }
#if 0
fprintf(errstd,"REBOOT=\"%s\"\n", reboot_arg);		    
#endif
		break;
#if !__MSDOS__
	    case 's':
		cfg_set(cf_options,"backup",param,NULL);
		break;
	    case 'S':
		cfg_set(cf_options,"force-backup",param,NULL);
		break;
	    case 't':
		test = 1;
		break;
	    case 'T':
	        tell_param = param;
	    	break;
	    case 'u':
		validate = 1;
		/* fall through */
	    case 'U':	/* argument to -u or -U is optional */
		uninstall = 1;
		if ((*argv)[2]) param = (*argv)+2;
		else if (argc && argv[1][0] != '-') {
		    param = *++argv;
		    argc--;
		}
		uninst_dev = param;
		break;
#endif /* !__MSDOS__ */
	    case 'v':
	        if ((*argv)[2]) param = (*argv)+2;
	        else if (argc && argv[1][0]>='0' && argv[1][0]<='9') {
	            param = *++argv;
	            argc--;
	        }
	        if (param) 
		    verbose = to_number(param);
		else
	            if (verbose<0) verbose = 1;
	            else verbose++;
	        if (verbose) errstd = stdout;
		break;
	    case 'V':
		version = 1;
		break;
#if !__MSDOS__
	    case 'w':
		cfg_set(cf_options,"nowarn",NULL,NULL);
		nowarn = 1;
		if ( (*argv)[2] == '+' ) nowarn = -1;
		break;
	    case 'x':
		cfg_set(cf_options,RAID_EXTRA_BOOT,param,NULL);
		break;
#endif /* !__MSDOS__ */
	    case 'X':
	        configuration();
		exit(0);
#if !__MSDOS__
	    case 'z':
		zflag++;	/* force zero of MBR 8-byte area */
		break;
	    case 'Z':
		cfg_set(cf_options,"bios-passes-dl",param,NULL);
		break;
#endif /* !__MSDOS__ */
	    default:
		usage(name);
	}
    }
    if (argc) usage(name);
#if !__MSDOS__
    if (!new_root) new_root = getenv("ROOT");
    if (new_root && *new_root) {
	pp_fd = fopen(PARTITIONS, "r");
	if (chroot(new_root) < 0) die("chroot %s: %s",new_root,strerror(errno));
	if (chdir("/dev") < 0)
	        warn("root at %s has no /dev directory", new_root);
	if (chdir("/") < 0) die("chdir /: %s",strerror(errno));
    }
    if (atexit(temp_remove)) die("atexit() failed");
    if (version+activate+instmbr+(tell_param!=NULL) > 1) usage(name);
    if (activate) do_activate(act1, act2);
#endif /* !__MSDOS__ */
    if (verbose > 0 || version) {
       printf("LILO version %d.%d%s%s", VERSION_MAJOR, VERSION_MINOR,
	      VERSION_EDIT, test ? " (test mode)" : "");
	if (version && verbose<=0) {
	    printf("\n");
	    return 0;
	}
	printf(", Copyright (C) 1992-1998 Werner Almesberger\n"
	       "Development beyond version 21 Copyright (C) 1999-2006 John Coffman\n"
	       );
        if (verbose>0) {
#if !__MSDOS__
#include <sys/utsname.h>
	    struct utsname buf;
#endif
            printf("Released %s%s and compiled at %s on %s%s\n",
		VERSION_DATE, comma ? "," : "", __TIME__, __DATE__, semi);
#if !__MSDOS__
	    if (verbose>=2 && uname(&buf)==0) {
		printf("Running %s kernel %s on %s\n",
		        buf.sysname, buf.release, buf.machine);
	    }
#endif
	}
        printf("\n");
        if (version) {
            if (verbose>=2) configuration();
            return 0;
        }
    }

    if (verbose > 0) errstd = stdout;
#if !__MSDOS__
    preload_types();
    if (geometric & (geometric-1))
	die ("Only one of '-g', '-l', or '-L' may be specified");

    if (tell_param) tell_early = strcasecmp(tell_param, "chrul")
    				&& strcasecmp(tell_param, "ebda");
    if (eflag) do_bitmap_edit(bitmap_file);
    if (tell_param && tell_early) probe_tell(tell_param);
    if (instmbr) do_install_mbr(act1, act2);
#endif /* !__MSDOS__ */    

    fd = cfg_open(config_file);
    more = fd<0 ? 0 : cfg_parse(cf_options);
    
#if !__MSDOS__
    temp = cfg_get_flag(cf_options,"nowarn");
    if (nowarn < 0) nowarn = 0;
    else nowarn = temp;
/* All warnings appear if very verbose modes used */
    if (verbose>=3) nowarn = 0;
#endif /* !__MSDOS__ */

    if (verbose>=6) printf("main: cfg_parse returns %d\n", more);

#if !__MSDOS__
    if (tell_param && !tell_early) probe_tell(tell_param);

    if (fstat(fd,&st) < 0)
	    die("fstat %s: %s", config_file, strerror(errno) );

    if (S_ISREG(st.st_mode)) {
        if (st.st_uid)
            warn("%s should be owned by root", config_file);
        else if (st.st_mode & (S_IWGRP | S_IWOTH))
	    warn("%s should be writable only for root", config_file);
        config_read = !!(st.st_mode & (S_IRGRP | S_IROTH));
    }

    if (!cfg_get_flag(cf_options,"nodevcache"))  preload_dev_cache();
    
    if (verbose<0 && cfg_get_strg(cf_options,"verbose"))
	verbose = to_number(cfg_get_strg(cf_options,"verbose"));
    if (verbose<0) verbose = 0;
    if (verbose) errstd = stdout;

    compact = cfg_get_flag(cf_options,"compact");
    geom = cfg_get_flag(cf_options,"geometric");
    linear = cfg_get_flag(cf_options,"linear");
    lba32  = cfg_get_flag(cf_options,"lba32");
    
    if (geom+linear+lba32 > 1)
	die("May specify only one of GEOMETRIC, LINEAR or LBA32");
    if (geometric) {
	if (geom+linear+lba32 > 0)  
	    warn("Ignoring entry '%s'", geom ? "geometric" :
	    	      linear ? "linear" : "lba32");
	geom = linear = lba32 = 0;
	if (geometric==AD_LBA32) lba32 = 1;
	else if (geometric==AD_LINEAR) linear = 1;
	else if (geometric==AD_GEOMETRIC) geom = 1;
    }    
    if (geom+linear+lba32 == 0) {
	warn("LBA32 addressing assumed");
	lba32 = 1;
    }
    if (linear) warn(
    	"LINEAR is deprecated in favor of LBA32:  LINEAR specifies 24-bit\n"
	"  disk addresses below the 1024 cylinder limit; LBA32 specifies 32-bit disk\n"
	"  addresses not subject to cylinder limits on systems with EDD-BIOS extensions;\n"
	"  use LINEAR only if you are aware of its limitations.");
    
    if (identify) identify_image(identify,ident_opt);

    if (uninstall)
	bsect_uninstall(uninst_dev ? uninst_dev : cfg_get_strg(cf_options,
	      "boot"),cfg_get_strg(cf_options,"backup"),validate);
#endif /* !__MSDOS__ */

    if (reboot_arg) {
	map_patch_first(cfg_get_strg(cf_options,"map") ? cfg_get_strg(
	      cf_options,"map") : MAP_FILE, reboot_arg);
	exit(0);
    }

#if !__MSDOS__
    if ( (param = cfg_get_strg(cf_options,"bios-passes-dl")) ) {
	if (strchr("YyTt1", *param)) bios_passes_dl = DL_GOOD;
	if (strchr("NnFf0", *param)) bios_passes_dl = DL_BAD;
    }
    if (bios_passes_dl == DL_NOT_SET) 	check_bios();	/* in probe.c */

    if (compact && (linear || lba32) && verbose>=4)
	warn("COMPACT may conflict with %s on some "
		"systems", lba32 ? "LBA32" : "LINEAR");

    geo_init(cfg_get_strg(cf_options,"disktab"));
#endif /* !__MSDOS__ */
    if (query)
	show_images(!cfg_get_strg(cf_options,"map") ? MAP_FILE :
	      cfg_get_strg(cf_options,"map"));

#if !__MSDOS__
/*************************************************/
/*  Doing a real install (may be test mode)      */
/*************************************************/

/* test for a RAID installation */
	raid_offset = raid_setup();
	if (verbose >= 2) {
	    printf("raid_setup returns offset = %08X  ndisk = %d\n", raid_offset, ndisk);
	    dump_serial_nos();    
	}

	if (verbose >=2 && do_md_install)
	    printf("raid flags: at bsect_open  0x%02X\n", raid_flags);

	bsect_open(
		cfg_get_strg(cf_options,"boot"),
		cfg_get_strg(cf_options,"map") ?
			cfg_get_strg(cf_options,"map") : MAP_FILE,
		cfg_get_strg(cf_options,"install"),
		cfg_get_strg(cf_options,"delay") ?
			timer_number(cfg_get_strg(cf_options,"delay")) : 0,
		cfg_get_strg(cf_options,"timeout") ?
			timer_number(cfg_get_strg(cf_options,"timeout")) : -1,
		raid_offset );
	if (more) {
	    cfg_init(cf_top);
	    if (cfg_parse(cf_top)) cfg_error("Syntax error");
	}
	
	temp = bsect_number();
	if (temp==0) die("No images have been defined.");
	else if (temp<0) die("Default image doesn't exist.");

#ifdef LCF_VIRTUAL
	check_vmdefault();
#endif
#ifdef LCF_NOKEYBOARD
	check_nokbdefault();
#endif
	check_fallback();
	check_unattended();
	
	if (verbose>=2) dump_serial_nos();
	if (do_md_install) raid_final();
	else if (!test) {
	    char *cp;
	    
	    if (verbose) printf("Writing boot sector.\n");

	    cp = cfg_get_strg(cf_options,"force-backup");
	    if (cp) bsect_update(cp,1,0);
	    else bsect_update(cfg_get_strg(cf_options,"backup"),0,0);

	} 
	else {
	    bsect_cancel();
	    if (passw)
	        printf("The password crc file has *NOT* been updated.\n");

	    printf("The boot sector and the map file have *NOT* been "
	      "altered.\n");
	}
	if (verbose>=4) dump_serial_nos();
	if (warnings) {
	    if (warnings>1)
	        printf("%d warnings were ", warnings);
            else printf("One warning was ");
            printf("%sed.\n", nowarn ? "suppress" : "issu");
	}
#else  /* __MSDOS__ */
	die("No option switches specified:  -q, -R, or -V");
#endif /* __MSDOS__ */
	
    return 0;
}
