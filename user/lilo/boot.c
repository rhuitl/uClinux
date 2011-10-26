/* boot.c  -  Boot image composition */
/*
Copyright 1992-1997 Werner Almesberger.
Copyright 1999-2006 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/
#define BIG_CHAIN 5

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/user.h>

#include "config.h"
#include "lilo.h"
#include "common.h"
#include "geometry.h"
#include "device.h"
#include "cfg.h"
#include "map.h"
#include "partition.h"
#include "boot.h"
#include "loader.h"

/* the number of sectors between the 15M memory hole and 1M
   this is the max. for a bzImage kernel + initrd unless "large-memory"
   or "mem=XXX" raises the limit  			*/
#define HIGH_SECTORS	((15-1)*1024*1024/SECTOR_SIZE) 
#define HIGH_4M		(3*1024*1024/SECTOR_SIZE)

static GEOMETRY geo;
static struct stat st;


static void check_size(char *name,int setup_secs,int sectors)
{
    if (sectors > setup_secs+MAX_KERNEL_SECS)
	die("Kernel %s is too big",name);
}


void boot_image(char *spec,IMAGE_DESCR *descr)
{
    BOOT_SECTOR buff;
    SETUP_HDR hdr;
    char *initrd;
    int setup,fd,sectors,hi_sectors=MAX_KERNEL_SECS*4;
    int modern_kernel;

    if (verbose > 0) {
	printf("Boot image: %s",spec);
	show_link(spec);	/* in common.c */
	printf("\n");
    }
    fd = geo_open(&geo,spec,O_RDONLY);
    if (fstat(fd,&st) < 0) die("fstat %s: %s",spec,strerror(errno));
    if (read(fd,(char *) &buff,SECTOR_SIZE) != SECTOR_SIZE)
	die("read %s: %s",spec,strerror(errno));
    setup = buff.sector[VSS_NUM] ? buff.sector[VSS_NUM] : SETUPSECS;
    if (read(fd,(char *) &hdr,sizeof(hdr)) != sizeof(hdr))
	die("read %s: %s",spec,strerror(errno));
    modern_kernel = !strncmp(hdr.signature,NEW_HDR_SIG,4) && hdr.version >=
      NEW_HDR_VERSION;
    if (modern_kernel) descr->flags |= FLAG_MODKRN;
    if (verbose > 1)
	printf("Setup length is %d sector%s.\n",setup,setup == 1 ? "" : "s");
    if (setup > MAX_SETUPSECS)
	die("Setup length exceeds %d maximum; kernel setup will overwrite boot loader", MAX_SETUPSECS);
    map_add(&geo,0,(st.st_size+SECTOR_SIZE-1)/SECTOR_SIZE);
    sectors = map_end_section(&descr->start,setup+SPECIAL_SECTORS+SPECIAL_BOOTSECT);
    if (!modern_kernel || !(hdr.flags & LFLAG_HIGH))
	check_size(spec,setup,sectors);
    else {
	if (hdr.start % PAGE_SIZE)
	    die("Can't load kernel at mis-aligned address 0x%08lx\n",hdr.start);
	descr->flags |= FLAG_LOADHI;	/* load kernel high */
	hi_sectors = sectors - setup;	/* number of sectors loaded high */
	hi_sectors *= 3;		/* account for decompression */
	if (hi_sectors < HIGH_4M) hi_sectors = HIGH_4M;
    }
    geo_close(&geo);
    if (verbose > 1)
	printf("Mapped %d sector%s.\n",sectors,sectors == 1 ? "" : "s");
    if ((initrd = cfg_get_strg(cf_kernel,"initrd")) || (initrd = cfg_get_strg(
      cf_options,"initrd"))) {
	if (!modern_kernel) die("Kernel doesn't support initial RAM disks");
	if (verbose > 0) {
	    printf("Mapping RAM disk %s",initrd);
	    show_link(initrd);
	    printf("\n");
	}
	fd = geo_open(&geo,initrd,O_RDONLY);
	if (fstat(fd,&st) < 0) die("fstat %s: %s",initrd,strerror(errno));
#if 1
	*(unsigned int *) descr->rd_size = st.st_size;
#else
	descr->rd_size = (st.st_size + SECTOR_SIZE - 1)/SECTOR_SIZE;
#endif
	map_begin_section();
	map_add(&geo,0,(st.st_size+SECTOR_SIZE-1)/SECTOR_SIZE);
	sectors = map_end_section(&descr->initrd,0);
	if (verbose > 1)
	    printf("RAM disk: %d sector%s.\n",sectors,sectors == 1 ?  "" :
	      "s");
	if (hi_sectors + sectors > HIGH_SECTORS
#ifndef LCF_INITRDLOW
	    && !cfg_get_flag(cf_options,"large-memory")
#endif
	    ) {
		descr->flags |= FLAG_TOOBIG;
		warn("The initial RAM disk is too big to fit between %s and\n"
				"   the 15M-16M memory hole."
#ifndef LCF_INITRDLOW
# if 0
							"  If your BIOS supports memory moves above 16M,\n"
				"   then you may specify \"large-memory\" in the configuration file\n"
				"   (/etc/lilo.conf)."
# else
							"  It will be loaded in the highest memory as\n"
				"   though the configuration file specified \"large-memory\" and it will\n"
				"   be assumed that the BIOS supports memory moves above 16M."
# endif
#endif
				, hi_sectors ? "the kernel" : "1M");
	}
	geo_close(&geo);
    }
}


void boot_device(char *spec,char *range,IMAGE_DESCR *descr)
{
    char *here;
    int start,secs;
    int sectors;

    if (verbose > 0) printf("Boot device: %s, range %s\n",spec,range);
    (void) geo_open(&geo,spec,O_NOACCESS);
    here = strchr(range,'-');
    if (here) {
	*here++ = 0;
	start = to_number(range);
	if ((secs = to_number(here)-start+1) < 0) die("Invalid range");
    }
    else {
	here = strchr(range,'+');
	if (here) {
	    *here++ = 0;
	    start = to_number(range);
	    secs = to_number(here);
	}
	else {
	    start = to_number(range);
	    secs = 1;
	}
    }
    map_add(&geo,start,secs);
    check_size(spec,SETUPSECS,sectors = map_end_section(&descr->start,60));
				/* this is a crude hack ... ----------^^*/
    geo_close(&geo);
    if (verbose > 1)
	printf("Mapped %d sector%s.\n",sectors,sectors == 1 ? "" : "s");
}


void do_map_drive(void)
{
    const char *tmp;
    char *end;
    int from,to;

    tmp = cfg_get_strg(cf_other,"map-drive");
    from = strtoul(tmp,&end,0);
    if (from > 0xff || *end)
	cfg_error("Invalid drive specification \"%s\"",tmp);
    cfg_init(cf_map_drive);
    (void) cfg_parse(cf_map_drive);
    tmp = cfg_get_strg(cf_map_drive,"to");
    if (!tmp) cfg_error("TO is required");
    to = strtoul(tmp,&end,0);
    if (to > 0xff || *end)
	cfg_error("Invalid drive specification \"%s\"",tmp);
    if (from || to) { /* 0 -> 0 is special */
	int i;

	for (i = 0; i < curr_drv_map; i++) {
	    if (drv_map[i] == ((to << 8) | from))
		die("Mapping 0x%02x to 0x%02x already exists",from,to);
	    if ((drv_map[i] & 0xff) == from)
		die("Ambiguous mapping 0x%02x to 0x%02x or 0x%02x",from,
		  drv_map[i] >> 8,to);
	}
	if (curr_drv_map == DRVMAP_SIZE)
	    cfg_error("Too many drive mappings (more than %d)",DRVMAP_SIZE);
	if (verbose > 1)
	    printf("  Mapping BIOS drive 0x%02x to 0x%02x\n",from,to);
	drv_map[curr_drv_map++] = (to << 8) | from;
    }
    cfg_unset(cf_other,"map-drive");
}

/* 
 *  Derive the name of the MBR from the partition name
 *  e.g.
 *   /dev/scsi/host2/bus0/target1/lun0/part2	=> disc
 *   /dev/sd/c0b0t0u0p7				=> c0b0t0u0
 *   /dev/sda11					=> sda
 *
 * If table==0, do no check for primary partition; if table==1, check
 * that we started from a primary (1-4) partition.
 *
 * A NULL return indicates an error
 *
 */
 
char *boot_mbr(const char *boot, int table)
{
#if 0
    char *part, *npart, *endptr;
    int i, j, k;
    
    npart = stralloc(boot);
    part = strrchr(npart, '/');
    if (!part++) die ("No '/' in partition/device name.");
    
    i = strlen(part);
    endptr = part + i - 1;
    
   /* j is the count of digits at the end of the name */ 
    j = 0;
    while (isdigit(*endptr)) { j++; --endptr; }
    if (j==0 && !table) die ("Not a partition name; no digits at the end.");
    
    k = !table || (j==1 && endptr[1]>='1' && endptr[1]<='4');
    
   /* test for devfs  partNN */
    if (strncmp(part, "part", 4)==0) {
    	strcpy(part, "disc");
    } 
   /* test for ..NpNN */
    else if (*endptr=='p' && isdigit(endptr[-1])) {
        *endptr = 0;  /* truncate the pNN part */
    }
   /* test for old /dev/hda3 or /dev/sda11 */
    else if (endptr[-1]=='d' && endptr[-3]=='/' &&
    		(endptr[-2]=='h' || endptr[-2]=='s')
	    ) {
        endptr[1] = 0;  /* truncate the NN part */
    }
    else 
	k = 0;

#else
    struct stat st;
    dev_t dev;
    DEVICE d;
    int mask, k;
    char *npart = NULL;
    
    k = 0;
    if (stat(boot,&st) < 0) die("stat %s: %s",boot,strerror(errno));
    dev = S_ISREG(st.st_mode) ? st.st_dev : st.st_rdev;
    if ( (mask = has_partitions(dev)) ) {
	k = dev & ~mask;
	k = !table ? 1 : k>=1 && k<=4;
	if (k) {
	    dev_open(&d, dev&mask, O_BYPASS);	/* bypass any open */
	    npart = stralloc(d.name); 
	    dev_close(&d);
	}
    }
    

#endif
    if (verbose>=3) {
        printf("Name: %s  yields MBR: %s  (with%s primary partition check)\n",
           boot, k ? npart : "(NULL)", table ? "" : "out");
    }

    if (k) return npart;
    else return NULL;
}



#define PART(s,n) (((struct partition *) (s)[0].par_c.ptable)[(n)])


void boot_other(char *loader,char *boot,char *part,IMAGE_DESCR *descr)
{
    int b_fd,p_fd,walk,found,size;
#ifdef LCF_BUILTIN
    BUILTIN_FILE *chain;
    char *cname;
#else
    int l_fd;
#endif
    unsigned char magic[2];
#ifdef BIG_CHAIN
    BOOT_SECTOR buff[BIG_CHAIN];
    BOOT_SECTOR zbuff;
    int mapped;
#else
    BOOT_SECTOR buff[SETUPSECS-1];
#endif
    struct stat st;
    char *pos;
    int i, code;
    int letter = 0;
    int unsafe;

    if (!loader) loader = DFL_CHAIN;
#ifdef LCF_BUILTIN
#ifndef LCF_SOLO_CHAIN
    if (strstr(loader,"os2")) {
	chain = &Os2_d;
	cname = "OS/2";
    }
    else
#endif
    {
	chain = &Chain;
	cname = "CHAIN";
    }
#endif
    if (part && strlen(part)>0 && strlen(part)<=2) {
    	if (part[1]==0 || part[1]==':') {
    	    letter = toupper(part[0]);
    	    if (letter>='C' && letter<='Z') {
    	    	letter += 0x80-'C';
    	    	part = NULL;
    	    }
    	    else letter = 0;
    	}
    }
    unsafe = cfg_get_flag(cf_other, "unsafe");
    if (!part && !unsafe) part = boot_mbr(boot, 1);
    /* part may still be NULL */

    if (verbose > 0) {
#ifdef LCF_BUILTIN
	printf("Boot other: %s%s%s, loader %s\n",
		boot,
		part ? ", on " : "",
		part ? part : "",
		cname);
#else
	printf("Boot other: %s%s%s, loader %s",
		boot,
		part ? ", on " : "",
		part ? part : "",
		loader);
	show_link(loader);
	printf("\n");
#endif
    }

#ifdef LCF_AUTOAUTO
    if (!cfg_get_flag(cf_other, "change")) {
    	autoauto = 1;	/* flag that change rules may be automatically inserted */
        do_cr_auto();
        autoauto = 0;
    }
#endif    

    if (unsafe) {
	(void) geo_open_boot(&geo,boot);
	if (part) die("TABLE and UNSAFE are mutually incompatible.");
    }
    else {
	b_fd = geo_open(&geo,boot,O_RDONLY);
	if (fstat(b_fd,&st) < 0)
	    die("fstat %s: %s",boot,strerror(errno));
	if (!geo.file) part_verify(st.st_rdev,0);
	else if (st.st_size > SECTOR_SIZE) {
	    warn("'other = %s' specifies a file that is longer\n"
	    	"    than a single sector.", boot);
	    if (st.st_size >= SECTOR_SIZE*(SETUPSECS-1) &&
	        read(b_fd, buff[0].sector, SECTOR_SIZE*(SETUPSECS-1)) == 
	    		SECTOR_SIZE*(SETUPSECS-1)   &&
	    	!strncmp((char*)buff[2].sector+2,"HdrS",4)
	    			) {
		warn("This file may actually be an 'image ='");
	    }
	}
	if (lseek(b_fd,(int) BOOT_SIG_OFFSET,SEEK_SET) < 0)
	    die("lseek %s: %s",boot,strerror(errno));
	if ((size = read(b_fd, &magic[0], 2)) != 2) {
	    if (size < 0) die("read %s: %s",boot,strerror(errno));
	    else die("Can't get magic number of %s",boot); }
	if (magic[0] != BOOT_SIGNATURE0 || magic[1] != BOOT_SIGNATURE1)
	    die("First sector of %s doesn't have a valid boot signature",boot);
    }

/* process the 'master-boot' or 'boot-as' options */
    i = cfg_get_flag(cf_other,"master-boot");
    pos = cfg_get_strg(cf_other,"boot-as");
    if (i && pos) die("'master-boot' and 'boot-as' are mutually exclusive 'other=' options");
    if (!i && !pos) {
	i = cfg_get_flag(cf_options,"master-boot");
	pos = cfg_get_strg(cf_options,"boot-as");
	if (i && pos) die("'master-boot' and 'boot-as' are mutually exclusive global options");
    }
    if (i) code = -1;	/* master-boot in use */
    else if (pos) {
	code = to_number(pos);
	if (code >= 80 && code <= 89) {
	    /* convert to 0x80 to 0x89 */
	    warn("Radix error, 'boot-as=%d' taken to mean 'boot-as=0x%x'",
	    			code, code+0x30);
	    code += 0x30;
	}
	if ( !((code>=0 && code<=3) || (code>=0x80 && code<=DEV_MASK)) )
	    die("Illegal BIOS device code specified in 'boot-as=0x%02x'", code);
    }
    else code = -2;
    
    if (code != -2) {
	curr_drv_map += 2;	/* add 2 spaces */
	if (curr_drv_map >= DRVMAP_SIZE)
	    cfg_error("Too many drive mappings (more than %d)",DRVMAP_SIZE);
	if (verbose > 1) {
	    char *s, n[8];
	    if (code==-1) s = "0/0x80";
	    else sprintf((s=n),"0x%02x", code);
	    printf("  Swapping BIOS boot drive with %s, as needed\n", s);
	}
	for (i=curr_drv_map-1; i>1; i--) drv_map[i] = drv_map[i-2];
	drv_map[0] = 0xFFFF;	/* reserve 2 slots */
	drv_map[1] = code<<8 | 0xFF;
    }

    memset(buff,0,sizeof(buff));
#ifdef BIG_CHAIN
    zbuff = buff[0];	/* zero out zbuff */
#endif
#ifndef LCF_BUILTIN
    if ((l_fd = open(loader,O_RDONLY)) < 0)
	die("open %s: %s",loader,strerror(errno));
    if ((size = read(l_fd,buff,sizeof(buff)+1)) < 0)
	die("read %s: %s",loader,strerror(errno));
    if (size > sizeof(buff))
	die("Chain loader %s is too big",loader);
    check_version(buff,STAGE_CHAIN);
#else
    size = chain->size;
    if (size > sizeof(buff))
	die("Chain loader %s is too big",loader);
    memcpy(buff, chain->data, size);
#endif
    if (!part) {
        p_fd = -1; /* pacify GCC */
        PART(buff,0).boot_ind = geo.device;
        PART(buff,0).start_sect = geo.start;     /* pseudo partition table */
        if (verbose > 0) printf("Pseudo partition start: %d\n", geo.start);
    }
    else {
	if ((p_fd = open(part,O_RDONLY)) < 0)
	    die("open %s: %s",part,strerror(errno));
	if (lseek(p_fd,(int) PART_TABLE_OFFSET,SEEK_SET) < 0)
	    die("lseek %s: %s",part,strerror(errno));
	if (read(p_fd,(char *) buff[0].par_c.ptable,PART_TABLE_SIZE) !=
	  PART_TABLE_SIZE)
	    die("read %s: %s",part,strerror(errno));
	found = 0;
	for (walk = 0; walk < PARTITION_ENTRIES; walk++)
	    if (!PART(buff,walk).sys_ind || PART(buff,walk).start_sect !=
	      geo.start) {
		/*
		 * Don't remember what this is supposed to be good for :-(
		 */
		if (PART(buff,walk).sys_ind != PART_DOS12 && PART(buff,walk).
		  sys_ind != PART_DOS16_SMALL && PART(buff,walk).sys_ind !=
		  PART_DOS16_BIG)
		  PART(buff,walk).sys_ind = PART_INVALID;
	    }
	    else {
		if (found) die("Duplicate entry in partition table");
		buff[0].par_c.offset = walk*PARTITION_ENTRY;
		PART(buff,walk).boot_ind = 0x80;
		found = 1;
	    }
	if (!found) die("Partition entry not found.");
	(void) close(p_fd);
    }
#ifndef LCF_BUILTIN
    (void) close(l_fd);
#endif
    buff[0].par_c.drive = geo.device;
    buff[0].par_c.head = letter ? letter : geo.device;
     		/* IBM boot manager passes drive letter in offset 0x25 */
    if (verbose>=5) printf("boot_other:  drive=0x%02x   logical=0x%02x\n",
    			buff[0].par_c.drive, buff[0].par_c.head);
    drv_map[curr_drv_map] = 0;
    prt_map[curr_prt_map] = 0;
    pos = (char *) buff+buff[0].par_c.drvmap;
    memcpy(pos,drv_map,sizeof(drv_map));
    memcpy(pos+sizeof(drv_map),prt_map,sizeof(prt_map)-2);

    size = (size + SECTOR_SIZE - 1) / SECTOR_SIZE;
#ifndef BIG_CHAIN
    map_add_zero();
#else
    if (size > SETUPSECS-1) {
	zbuff.sector[VSS_NUM] = mapped = size+1;
	map_add_sector(zbuff.sector);
    }
    else {
	map_add_zero();
	mapped = SETUPSECS;
    }
#endif
    for (i = 0; i < size; i++) map_add_sector(&buff[i]);
    for (i = size; i < SETUPSECS-1; i++) map_add_zero();
    map_add(&geo,0,1);

#ifndef BIG_CHAIN
    (void) map_end_section(&descr->start,SETUPSECS+SPECIAL_SECTORS);
	/* size is known */
    geo_close(&geo);
    if (verbose > 1)
	printf("Mapped %d (%d+1+1) sectors.\n",
		SETUPSECS+SPECIAL_SECTORS, SETUPSECS);
#else
    (void) map_end_section(&descr->start, mapped+SPECIAL_SECTORS+SPECIAL_BOOTSECT);
	/* size is known */
    geo_close(&geo);
    if (verbose > 1)
	printf("Mapped %d (%d+1+1) sectors.\n",
		mapped+SPECIAL_SECTORS, mapped);
#endif
}
