/* partition.c  -  Partition table handling */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <time.h>
#include <dirent.h>
#include "config.h"
#include "lilo.h"
#include "common.h"
#include "cfg.h"
#include "device.h"
#include "geometry.h"
#include "partition.h"
#include "boot.h"
#include "loader.h"

#if __GLIBC__ < 2 || __GLIBC_MINOR__ < 1
#if defined(_syscall5) && defined(__NR__llseek)
       
       _syscall5(int,  _llseek,  unsigned int,  fd, unsigned int, hi,
           unsigned int, lo, lloff_t *, res, unsigned int, wh);
       int _llseek(unsigned int fd,  unsigned  int  offset_high,
           unsigned  int  offset_low,  lloff_t * result, unsigned int whence);

       lloff_t lseek64(unsigned int fd, lloff_t offs, unsigned int whence)
       { lloff_t res;
       	   return _llseek(fd, offs>>32, offs, &res, whence) < 0  ?
       			 (lloff_t)(-1) : res;
       }

#else
/* last ditch attempt on small disks, and very old systems */
# warning "*****************************************"
# warning "***** no 64 bit lseek is available ******"
# warning "***** using 23 bit sector addresses *****"
# warning "*****************************************"
# define lseek64 lseek
#endif
#endif

static
int anywhere(void *buf, char *str)
{
    int k, n;
    void *s;
    
    k = strlen(str);
    n = SECTOR_SIZE-k;
    s = memchr(buf, *str, n);
    while(s) {
	if (!strncmp(s, str, k)) return 1;
	s++;
	n = SECTOR_SIZE - k - (int)(s-buf);
	s = memchr(s, *str, n);
    }
    return 0;
}



/* identify partitions which would be destroyed if the boot block
   is overwritten:
   
   known problems occur for:
   	XFS
   	NTFS
   	DOS FAT (relocation will fix)

*/
int part_nowrite(char* device)
{
    int fd;
    BOOT_SECTOR bs;
    
    int ret=PTW_OKAY;	/* say ok, unless we recognize a problem partition */
if ( !(do_md_install && extra==X_MBR_ONLY) ) {
    if ((fd = open(device, O_RDONLY)) < 0) pdie("part_nowrite check:");
    if (read(fd, bs.sector, sizeof(bs)) != SECTOR_SIZE) pdie("part_nowrite: read:");
    
/* check for XFS */
    if (!strncmp("XFSB", (char*)bs.sector, 4)) ret=PTW_XFS;
    
/* check for NTFS */
    else if (	!strncmp("NTFS", bs.par_d.system, 4)
		|| anywhere(bs.sector,"NTLDR")  ) ret=PTW_NTFS;

/* check for HPFS */
    else if (	!strncmp("OS2", bs.par_d.system, 3)
		|| anywhere(bs.sector,"OS2LDR")  ) ret=PTW_OS2;

/* check for DOS FAT */
    else if (
	(bs.par_d.bpb.media_descriptor >= 0xF8 || bs.par_d.bpb.media_descriptor == 0xF0)
	&& *(short*)bs.par_d.bpb.bytes_per_sector == SECTOR_SIZE
	&& (bs.par_d.bpb.number_of_FATs==1 || bs.par_d.bpb.number_of_FATs==2)
    /* sectors_per_cluster is a power of 2, meaning only 1 bit is on */
	&& bs.par_d.bpb.sectors_per_cluster
	&& (bs.par_d.bpb.sectors_per_cluster & (bs.par_d.bpb.sectors_per_cluster-1))==0
				) {
		ret=PTW_DOS;
#if 0
/* this, it turns out is from Windows 98, so no caution here on NT */
    		if (anywhere(bs.sector,"WINBOOT SYS")) ret+=PTW_NTFS;
#endif
    }
    
/* check for SWAP -- last check, as 'bs' is overwritten */
    else if (*(int*)bs.sector == 0xFFFFFFFEU) {
	if (lseek(fd, (PAGE_SIZE)-SECTOR_SIZE, SEEK_SET) != (PAGE_SIZE)-SECTOR_SIZE)
	    pdie("part_nowrite lseek:");
	if (SECTOR_SIZE != read(fd, bs.sector, sizeof(bs)) ) pdie("part_nowrite swap check:");
	if (!strncmp((char*)bs.sector+SECTOR_SIZE-10,"SWAPSPACE2",10)
	    || !strncmp((char*)bs.sector+SECTOR_SIZE-10,"SWAP-SPACE",10) ) ret=PTW_SWAP;
    }

/* didn't recognize the superblock type, so assume it is okay */    
    else ret=PTW_OKAY;
    
    close(fd);

} /* raid install with X_MBR_ONLY in use */
    if (verbose>=6) printf("part_nowrite: %d\n", ret);    
    
    return ret;
}


void part_verify(int dev_nr,int type)
{
    GEOMETRY geo;
    DEVICE dev;
    char backup_file[PATH_MAX+1];
    int fd, bck_file, part, size, lin_3d, cyl;
    unsigned int second, base;
    struct partition part_table[PART_MAX];
    int mask, i, pe, Linux, dos, mbr;
    unsigned char boot_sig[2];
    BOOT_PARAMS_1 bs;
    
    if (!has_partitions(dev_nr) || !(mask = P_MASK(dev_nr)) || !(dev_nr & mask)
#if 0
     || (dev_nr & mask) > PART_MAX
#endif
     	) return;

    if (verbose >= 4) printf("part_verify:  dev_nr=%04x, type=%d\n", dev_nr, type);
    geo_get(&geo,dev_nr & ~mask,-1,1);
    fd = dev_open(&dev,dev_nr & ~mask,cfg_get_flag(cf_options,"fix-table")
      && !test ? O_RDWR : O_RDONLY);
    part = (pe = dev_nr & mask)-1;
#if 1
    if (type) {
	if (lseek(fd, 0L, SEEK_SET) != 0 ||
	    read(fd, &bs, sizeof(bs)) != sizeof(bs) ) pdie("bs read");
	if (*(int*)bs.signature==EX_MAG_HL) mbr = bs.stage;
	else mbr = STAGE_MBR;
    } else mbr = STAGE_MBR;
#endif
    if (lseek(fd, PART_TABLE_OFFSET, SEEK_SET) < 0) pdie("lseek partition table");
    if (!(size = read(fd,(char *) part_table, sizeof(struct partition)*
      PART_MAX))) die("Short read on partition table");
    if (size < 0) pdie("read partition table");
    if ( read(fd, &boot_sig, sizeof(boot_sig)) != sizeof(boot_sig)  ||
	boot_sig[0] != BOOT_SIGNATURE0 || boot_sig[1] != BOOT_SIGNATURE1 )
	die("read boot signature failed");

    if (verbose>=5) printf("part_verify:  part#=%d\n", pe);

    second=base=0;
    for (i=0; i<PART_MAX; i++) {
	if (is_extd_part(part_table[i].sys_ind)) {
	    if (!base) base = part_table[i].start_sect;
	    else die("invalid partition table: second extended partition found");
	}
    }
    i=5;
    while (i<=pe && base) {
        if (lseek64(fd, LLSECTORSIZE*(base+second) + PART_TABLE_OFFSET, SEEK_SET) < 0)
            die("secondary lseek64 failed");
	if (read(fd, part_table, sizeof(part_table)) != sizeof(part_table)) die("secondary read pt failed");
	if ( read(fd, &boot_sig, sizeof(boot_sig)) != sizeof(boot_sig)  ||
	    boot_sig[0] != BOOT_SIGNATURE0 || boot_sig[1] != BOOT_SIGNATURE1 )
	    die("read second boot signature failed");
        if (is_extd_part(part_table[1].sys_ind)) second=part_table[1].start_sect;
        else base = 0;
        i++;
        part=0;
    }
#if 1
    if (type && pe>0 && pe<=(mbr==STAGE_MBR2?63:PART_MAX)
    	     && !(part_table[part].boot_ind&0x80) )
	warn("Partition %d on %s is not marked Active.",
		pe, dev.name);
#endif
    i = part_table[part].sys_ind;

    Linux =   i == PART_LINUX_MINIX ||
	      i == PART_LINUX_NATIVE ||
	      is_extd_part(i);

    i &= ~HIDDEN_OFF;
    dos =     i == PART_DOS12 ||
	      i == PART_DOS16_SMALL ||
	      i == PART_DOS16_BIG ||
	      i == PART_FAT32 ||
	      i == PART_FAT32_LBA ||
	      i == PART_FAT16_LBA ||
	      i == PART_NTFS ||
	      i == PART_OS2_BOOTMGR ;

    if (type && !Linux) {
	warn("partition type 0x%02X"" on device 0x%04X is a dangerous place for\n"
             "    a boot sector.%s",
			part_table[part].sys_ind, dev_nr,
	dos ? "  A DOS/Windows/OS2 system may be rendered unbootable."
		"\n  The backup copy of this boot sector should be retained."
		: "" );
#if 0
	if (!dos && !cfg_get_flag(cf_options,"ignore-table"))
	    die("You may proceed by using either '-P ignore' or 'ignore-table'");
#else
	if (!yesno("\nProceed? ", 0)) exit(0);
#endif
    }
    cyl = part_table[part].cyl+((part_table[part].sector >> 6) << 8);
    lin_3d = (part_table[part].sector & 63)-1+(part_table[part].head+
      cyl*geo.heads)*geo.sectors;
    if (pe <= PART_MAX &&
	    (lin_3d > part_table[part].start_sect || (lin_3d <
	    part_table[part].start_sect && cyl != BIOS_MAX_CYLS-1)) ) {
	warn("Device 0x%04X: Inconsistent partition table, %d%s entry",
	  dev_nr & ~mask,part+1,!part ? "st" : part == 1 ? "nd" : part ==
	  2 ? "rd" : "th");
        if (!nowarn)
	fprintf(errstd,"  CHS address in PT:  %d:%d:%d  -->  LBA (%d)\n",
		cyl,
		part_table[part].head,
		part_table[part].sector & 63,
		lin_3d);
	cyl = part_table[part].start_sect/geo.sectors/geo.heads;
        if (!nowarn)
	fprintf(errstd,"  LBA address in PT:  %d  -->  CHS (%d:%d:%d)\n",
		part_table[part].start_sect,
		cyl,
		part_table[part].head = (part_table[part].start_sect/geo.sectors) % geo.heads,
		part_table[part].sector = (part_table[part].start_sect % geo.sectors)+1
		);
	if (cyl >= BIOS_MAX_CYLS) cyl = BIOS_MAX_CYLS-1;
	part_table[part].sector |= (cyl >> 8)<<6;
	part_table[part].cyl = cyl & 0xff;
	if (!cfg_get_flag(cf_options,"fix-table") && !cfg_get_flag(cf_options,
	  "ignore-table")) die("Either FIX-TABLE or IGNORE-TABLE must be specified\n"
			"If not sure, first try IGNORE-TABLE (-P ignore)");
	if (test || cfg_get_flag(cf_options,"ignore-table")) {
	    warn("The partition table is *NOT* being adjusted.");
	} else {
	    sprintf(backup_file,BACKUP_DIR "/part.%04X",dev_nr & ~mask);
	    if ((bck_file = creat(backup_file,0644)) < 0)
		die("creat %s: %s",backup_file,strerror(errno));
	    if (!(size = write(bck_file,(char *) part_table,
	      sizeof(struct partition)*PART_MAX)))
		die("Short write on %s",backup_file);
	    if (size < 0) pdie(backup_file);
	    if (close(bck_file) < 0)
		die("close %s: %s",backup_file,strerror(errno));
	    if (verbose > 0)
		printf("Backup copy of partition table in %s\n",backup_file);
	    printf("Writing modified partition table to device 0x%04X\n",
	      dev_nr & ~mask);
	    if (lseek(fd,PART_TABLE_OFFSET,SEEK_SET) < 0)
		pdie("lseek partition table");
	    if (!(size = write(fd,(char *) part_table,sizeof(struct partition)*
	      PART_MAX))) die("Short write on partition table");
	    if (size < 0) pdie("write partition table");
	}
    }
    dev_close(&dev);
}


CHANGE_RULE *change_rules = NULL;


void do_cr_reset(void)
{
    CHANGE_RULE *next;

    while (change_rules) {
	next = change_rules->next;
	free((char *) change_rules->type);
	free(change_rules);
	change_rules = next;
    }
}


static unsigned char cvt_byte(const char *s)
{
    char *end;
    unsigned int value;

    value = strtoul(s,&end,0);
    if (value > 255 || *end) cfg_error("\"%s\" is not a byte value",s);
    return value;
}


static void add_type(const char *type,int normal,int hidden)
{
    CHANGE_RULE *rule;

    for (rule = change_rules; rule; rule = rule->next)
	if (!strcasecmp(rule->type,type))
	    die("Duplicate type name: \"%s\"",type);
    rule = alloc_t(CHANGE_RULE);
    rule->type = stralloc(type);
    rule->normal = normal == -1 ? hidden ^ HIDDEN_OFF : normal;
    rule->hidden = hidden == -1 ? normal ^ HIDDEN_OFF : hidden;
    rule->next = change_rules;
    change_rules = rule;
}


void do_cr_type(void)
{
    const char *normal,*hidden;

    cfg_init(cf_change_rule);
    (void) cfg_parse(cf_change_rule);
    normal = cfg_get_strg(cf_change_rule,"normal");
    hidden = cfg_get_strg(cf_change_rule,"hidden");
    if (normal)
	add_type(cfg_get_strg(cf_change_rules,"type"),cvt_byte(normal),
	  hidden ? cvt_byte(hidden) : -1);
    else {
	if (!hidden)
	    cfg_error("At least one of NORMAL and HIDDEN must be present");
	add_type(cfg_get_strg(cf_change_rules,"type"),cvt_byte(hidden),-1);
    }
    cfg_unset(cf_change_rules,"type");
}


void do_cr(void)
{
    cfg_init(cf_change_rules);
    (void) cfg_parse(cf_change_rules);
}


#if defined(LCF_REWRITE_TABLE) && !defined(LCF_READONLY)

/*
 * Rule format:
 *
 * +------+------+------+------+
 * |drive |offset|expect| set  |
 * +------+------+------+------+
 *     0      1      2      3
 */

static void add_rule(unsigned char bios,unsigned char offset,
  unsigned char expect,unsigned char set)
{
    int i;

    if (curr_prt_map == PRTMAP_SIZE)
	cfg_error("Too many change rules (more than %s)",PRTMAP_SIZE);
    if (verbose >= 3)
	printf("  Adding rule: disk 0x%02x, offset 0x%x, 0x%02x -> 0x%02x\n",
	    bios,PART_TABLE_OFFSET+offset,expect,set);
    prt_map[curr_prt_map] = (set << 24) | (expect << 16) | (offset << 8) | bios;
    for (i = 0; i < curr_prt_map; i++) {
	if (prt_map[i] == prt_map[curr_prt_map])
	  die("Repeated rule: disk 0x%02x, offset 0x%x, 0x%02x -> 0x%02x",
	    bios,PART_TABLE_OFFSET+offset,expect,set);
	if ((prt_map[i] & 0xffff) == ((offset << 8) | bios) &&
	  (prt_map[i] >> 24) == expect)
	    die("Redundant rule: disk 0x%02x, offset 0x%x: 0x%02x -> 0x%02x "
	      "-> 0x%02x",bios,PART_TABLE_OFFSET+offset,
	     (prt_map[i] >> 16) & 0xff,expect,set);
    }
    curr_prt_map++;
}

#endif


static int has_partition;

static CHANGE_RULE *may_change(unsigned char sys_ind)
{
    CHANGE_RULE *cr = change_rules;
    
    while (cr) {
        if (cr->normal == sys_ind || cr->hidden == sys_ind) return cr;
        cr = cr->next;
    }
    return NULL;
}


void do_cr_auto(void)
{
    GEOMETRY geo;
    struct stat st;
    char *table, *table2, *other;
    int partition, pfd, i, j;
    struct partition part_table[PART_MAX];

    if (autoauto) has_partition = 0;
    other = identify ? cfg_get_strg(cf_identify, "other")
		     : cfg_get_strg(cf_top, "other");
    if (verbose > 4) printf("do_cr_auto: other=%s has_partition=%d\n",
        other, has_partition);
#if 0
    i = other[strlen(other)-1] - '0';
    if (i>PART_MAX || i<1) return;
#endif
    table = cfg_get_strg(cf_other,"table");
    table2 = boot_mbr(other, 1);	/* get possible default */
    if (!table) table = table2;
    
    if (!table && autoauto) return;
    if (table && autoauto && !table2) cfg_error("TABLE may not be specified");
   
    if (has_partition) cfg_error("AUTOMATIC must be before PARTITION");
    if (!table) cfg_error("TABLE must be set to use AUTOMATIC");
    /*    
     */
    if (stat(table,&st) < 0) die("stat %s: %s",table,strerror(errno));
    geo_get(&geo,st.st_rdev & D_MASK(st.st_rdev),-1,1);
    partition = st.st_rdev & P_MASK(st.st_rdev);
    if (!S_ISBLK(st.st_mode) || partition)
	cfg_error("\"%s\" doesn't contain a primary partition table",table);
    pfd = open(table, O_RDONLY);
    if (pfd<0) die("Cannot open %s", table);
    if (lseek(pfd, PART_TABLE_OFFSET, SEEK_SET)!=PART_TABLE_OFFSET)
	die("Cannot seek to partition table of %s", table);
    if (read(pfd, part_table, sizeof(part_table))!=sizeof(part_table))
	die("Cannot read Partition Table of %s", table);
    close(pfd);
    partition = other[strlen(other)-1] - '0';
    if (verbose > 3) printf("partition = %d\n", partition);
    for (j=i=0; i<PART_MAX; i++)
	if (may_change(part_table[i].sys_ind)) j++;

    if (j>1)
#if defined(LCF_REWRITE_TABLE) && !defined(LCF_READONLY)
    for (i=0; i<PART_MAX; i++) {
    	CHANGE_RULE *cr;
	if ((cr=may_change(part_table[i].sys_ind))) {
	    j = i*PARTITION_ENTRY + PART_TYPE_ENT_OFF;
	    if (autoauto) {
	        warn("CHANGE AUTOMATIC assumed after \"other=%s\"", other);
	        autoauto = 0;  /* suppress further warnings */
	    }    
	    if (i == partition-1)
		add_rule(geo.device, j, cr->hidden, cr->normal);
	    else
		add_rule(geo.device, j, cr->normal, cr->hidden);
	}
    }
#else
    warn("This LILO is compiled without REWRITE_TABLE;\n"
       "   unable to generate CHANGE/AUTOMATIC change-rules");
#endif
}



void do_cr_part(void)
{
    GEOMETRY geo;
    struct stat st;
    char *tmp;
    int partition,part_base;

    tmp = cfg_get_strg(cf_change,"partition");
    if (stat(tmp,&st) < 0) die("stat %s: %s",tmp,strerror(errno));
    geo_get(&geo,st.st_rdev & D_MASK(st.st_rdev),-1,1);
    partition = st.st_rdev & P_MASK(st.st_rdev);
    if (!S_ISBLK(st.st_mode) || !partition || partition > PART_MAX)
	cfg_error("\"%s\" isn't a primary partition",tmp);
    part_base = (partition-1)*PARTITION_ENTRY;
    has_partition = 1;   
    cfg_init(cf_change_dsc);
    (void) cfg_parse(cf_change_dsc);
    tmp = cfg_get_strg(cf_change_dsc,"set");
    if (tmp) {
#if defined(LCF_REWRITE_TABLE) && !defined(LCF_READONLY)
	CHANGE_RULE *walk;
	char *here;
	int hidden;

	here = (void*)NULL;	/* quiet GCC */
	hidden = 0;		/* quiet GCC */
	if (strlen(tmp) < 7 || !(here = strrchr(tmp,'_')) ||
	  ((hidden = strcasecmp(here+1,"normal")) &&
	  strcasecmp(here+1,"hidden")))
	    cfg_error("Type name must end with _normal or _hidden");
	*here = 0;
	for (walk = change_rules; walk; walk = walk->next)
	    if (!strcasecmp(walk->type,tmp)) break;
	if (!walk) cfg_error("Unrecognized type name");
	add_rule(geo.device,part_base+PART_TYPE_ENT_OFF,hidden ? walk->normal :
	  walk->hidden,hidden ? walk->hidden : walk->normal);
#else
	die("This LILO is compiled without REWRITE_TABLE and doesn't support "
	  "the SET option");
#endif
    }
    if (cfg_get_flag(cf_change_dsc,"activate")) {
#if defined(LCF_REWRITE_TABLE) && !defined(LCF_READONLY)
	add_rule(geo.device,part_base+PART_ACT_ENT_OFF,0x00,0x80);
	if (cfg_get_flag(cf_change_dsc,"deactivate"))
	    cfg_error("ACTIVATE and DEACTIVATE are incompatible");
#else
	die("This LILO is compiled without REWRITE_TABLE and doesn't support "
	  "the ACTIVATE option");
#endif
    }
    if (cfg_get_flag(cf_change_dsc,"deactivate"))
#if defined(LCF_REWRITE_TABLE) && !defined(LCF_READONLY)
	add_rule(geo.device,part_base+PART_ACT_ENT_OFF,0x80,0x00);
#else
	die("This LILO is compiled without REWRITE_TABLE and doesn't support "
	  "the DEACTIVATE option");
#endif
    cfg_unset(cf_change,"partition");
}


void do_change(void)
{
    cfg_init(cf_change);
    has_partition = 0;
    (void) cfg_parse(cf_change);
}


void preload_types(void)
{
#if 0 /* don't know if it makes sense to add these too */
    add_type("Netware", 0x64, 0x74);
    add_type("OS2_BM", 0x0a, 0x1a);
#endif
    add_type("OS2_HPFS", 0x07, 0x17);

    add_type("FAT16_lba", PART_FAT16_LBA, -1);
    add_type("FAT32_lba", PART_FAT32_LBA, -1);
    add_type("FAT32", PART_FAT32, -1);
    add_type("NTFS", PART_NTFS, -1);
    add_type("DOS16_big", PART_DOS16_BIG, -1);
    add_type("DOS16_small", PART_DOS16_SMALL, -1);
    add_type("DOS12", PART_DOS12, -1);
}



#define PART_BEGIN	0x1be
#define PART_NUM	4
#define PART_SIZE	16
#define PART_ACTIVE	0x80
#define PART_INACTIVE	0


void do_activate(char *part, char *which)
{
#if 1
    int part_max, count, number, fd;
    struct partition pt [PART_MAX_MAX+1];
    long long daddr [PART_MAX_MAX+1];
    int modify=0;
    
    part_max = read_partitions(part, extended_pt ? PART_MAX_MAX : 0,
    					NULL, pt, daddr);
/*    printf("part_max=%d\n", part_max); */
    if (!which) {	/* one argument: display active partition */
	for (count=0; count < part_max; count++) {
	    if (pt[count].boot_ind) {
		printf("%s%d\n",part,count+1);
		exit(0);
	    }
	}
	printf("No active partition found on %s\n",part);
	exit(0);
    }
    number = to_number(which);
    if (number < 0 || number > part_max)
	die("%s: not a valid partition number (1-%d)",which,part_max);

    if (number && !pt[number-1].sys_ind) die("Cannot activate an empty partition");
    number--;	/* we are zero-based from here on */

    if ((fd = open(part, O_RDWR)) < 0)
	die("open %s: %s",part,strerror(errno));
    for (count=0; count<part_max; count++) {
    	unsigned char flag = count==number ? PART_ACTIVE : PART_INACTIVE;
    	if (pt[count].sys_ind && pt[count].boot_ind != flag) {
    	    pt[count].boot_ind = flag;
	    printf("pt[%d] -> %2x\n", count+1, (int)flag);
	    if (lseek64(fd, daddr[count], SEEK_SET) < 0) die("PT lseek64 failed");
	    if (!test)
	    if (write(fd, &pt[count], sizeof(pt[0])) != sizeof(pt[0]) )
		die("PT write failure");
	    modify++;
    	}
    }
    close(fd);
    if (modify)
	printf("The partition table has%s been updated.\n", test ? " *NOT*" : "");
    else
	printf("No partition table modifications are needed.\n");
#else
    struct stat st;
    int fd,number,count;
    unsigned char flag, ptype;

    if ((fd = open(part, !which ? O_RDONLY : O_RDWR)) < 0)
	die("open %s: %s",part,strerror(errno));
    if (fstat(fd,&st) < 0) die("stat %s: %s",part,strerror(errno));
    if (!S_ISBLK(st.st_mode)) die("%s: not a block device",part);
    if (verbose >= 1) {
       printf("st.st_dev = %04X, st.st_rdev = %04X\n",
       				(int)st.st_dev, (int)st.st_rdev);
    }
    if ((st.st_rdev & has_partitions(st.st_rdev)) != st.st_rdev)
        die("%s is not a master device with a primary partition table", part);
    if (!which) {	/* one argument: display active partition */
	for (count = 1; count <= PART_NUM; count++) {
	    if (lseek(fd,PART_BEGIN+(count-1)*PART_SIZE,SEEK_SET) < 0)
		die("lseek: %s",strerror(errno));
	    if (read(fd,&flag,1) != 1) die("read: %s",strerror(errno));
	    if (flag == PART_ACTIVE) {
		printf("%s%d\n",part,count);
		exit(0);
	    }
	}
	die("No active partition found on %s",part);
    }
    number = to_number(which);
    if (number < 0 || number > 4)
	die("%s: not a valid partition number (1-4)",which);
    for (count = 1; count <= PART_NUM; count++) {
	if (lseek(fd,PART_BEGIN+(count-1)*PART_SIZE+4,SEEK_SET) < 0)
	    die("lseek: %s",strerror(errno));
	if (read(fd,&ptype,1) != 1) die("read: %s",strerror(errno));
	if (count == number && ptype==0) die("Cannot activate an empty partition");
    }
    if (test) {
        printf("The partition table of  %s  has *NOT* been updated\n",part);
    }
    else for (count = 1; count <= PART_NUM; count++) {
	if (lseek(fd,PART_BEGIN+(count-1)*PART_SIZE,SEEK_SET) < 0)
	    die("lseek: %s",strerror(errno));
	flag = count == number ? PART_ACTIVE : PART_INACTIVE;
	if (write(fd,&flag,1) != 1) die("write: %s",strerror(errno));
    }
#endif
    exit(0);
}


void do_install_mbr(char *part, char *what)
{
    int fd, i;
#ifndef LCF_BUILTIN
    int nfd;
#endif
    struct stat st;
    BOOT_SECTOR buf;
    char *cp;
    
    if (!what) what = DFL_MBR;
    extended_pt |= !!strchr(what,'x') || !!strchr(what,'X') || !!strchr(what,'2');
    if ((fd=open(part,O_RDWR)) < 0) die("Cannot open %s: %s", part,strerror(errno));
    if (fstat(fd,&st) < 0) die("stat: %s : %s", part,strerror(errno));
    if (!S_ISBLK(st.st_mode) && !force_fs) die("%s not a block device",part);
    if (st.st_rdev != (st.st_rdev & has_partitions(st.st_rdev)))
	die("%s is not a master device with a primary parition table",part);
    if (read(fd,&buf,SECTOR_SIZE) != SECTOR_SIZE) die("read %s: %s",part, strerror(errno));

    cp = cfg_get_strg(cf_options,"force-backup");
    i = (cp!=NULL);
    if (!cp) cp = cfg_get_strg(cf_options,"backup");
    make_backup(cp, i, &buf, st.st_rdev, part);
    
#ifndef LCF_BUILTIN    
    if ((nfd=open(what,O_RDONLY)) < 0) die("Cannot open %s: %s",what,strerror(errno));
    if (read(nfd,buf,MAX_BOOT_SIZE) != MAX_BOOT_SIZE) die("read %s: %s",what,strerror(errno));
#else
    memcpy(&buf, extended_pt ? Mbr2.data : Mbr.data, MAX_BOOT_SIZE);
#endif    
    ((unsigned char *)&buf.boot.boot_ind)[0] = BOOT_SIGNATURE0;
    ((unsigned char *)&buf.boot.boot_ind)[1] = BOOT_SIGNATURE1;
    if (zflag) {
        buf.boot.mbz =
        buf.boot.marker =
        buf.boot.volume_id = 0;
#if BETA_TEST || 1
        if ((cp=cfg_get_strg(cf_options,RAID_EXTRA_BOOT))) {
	    buf.boot.volume_id = strtoul(cp, NULL, 16);
        }
#endif
    } else if (buf.boot.volume_id == 0) {
#if 0
    	i = st.st_rdev;
    	i %= PRIME;		/* modulo a prime number; eg, 2551, 9091 */
    	i += SMALL_PRIME;
        srand(time(NULL));	/* seed the random number generator */
        while (i--) rand();
        *(int*)&buf[PART_TABLE_OFFSET - 6] = rand();  /* insert serial number */
        if (*(short*)&buf[PART_TABLE_OFFSET - 2] == 0)
            *(short*)&buf[PART_TABLE_OFFSET - 2] = MAGIC_SERIAL;
#else
	buf.boot.volume_id = new_serial(st.st_rdev);
	buf.boot.marker = MAGIC_SERIAL;
#endif
    }
    
    if (lseek(fd,0,SEEK_SET) != 0) die("seek %s; %s", part, strerror(errno));
    if (!test) {
	if (write(fd,&buf,SECTOR_SIZE) != SECTOR_SIZE)
		die("write %s: %s",part,strerror(errno));
    }
    close(fd);
#ifndef LCF_BUILTIN
    close(nfd);
#endif
    printf("The Master Boot Record of  %s  has %sbeen updated.\n", part, test ? "*NOT* " : "");
    exit(0);
}



/* partition table read */
int read_partitions(char *part, int max, int *volid,
		struct partition *p, long long *where)
{
    int fd, i;
    unsigned int second, base;
    unsigned char boot_sig[2];
    struct partition pt[PART_MAX];
    BOOT_PARAMS_1 hdr;
    struct stat st;
    long long daddr;

    if ((fd=open(part,O_RDONLY))<0) die("Cannot open '%s'", part);
    if (fstat(fd,&st)<0) die("Cannot fstat '%s'", part);
    if (!S_ISBLK(st.st_mode)) die("Not a block device '%s'", part);
    i = st.st_rdev;
    if (!has_partitions(i) || (P_MASK(i)&i) )
	die("Not a device with partitions '%s'", part);

    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) die("read header");
    if (!strncmp(hdr.signature, "LILO", 4) && hdr.stage == STAGE_MBR2 &&
	max == 0) max = PART_MAX_MAX;
    else if (max == 0) max = PART_MAX;
    if (lseek(fd, PART_TABLE_OFFSET, SEEK_SET)<0) die("lseek failed");
    if (read(fd, pt, sizeof(pt)) != sizeof(pt)) die("read pt failed");
    if ( read(fd, &boot_sig, sizeof(boot_sig)) != sizeof(boot_sig)  ||
	boot_sig[0] != BOOT_SIGNATURE0 || boot_sig[1] != BOOT_SIGNATURE1 )
		die("read boot signature failed");
    if (volid) {
	if (lseek(fd, MAX_BOOT_SIZE+2, SEEK_SET)<0) die("lseek vol-ID failed");
	if (read(fd, volid, sizeof(*volid)) != sizeof(*volid))
	    die("read vol-ID failed");
/*	printf(" vol-ID: %08X\n", second);	*/
    }
/*    printf("%s\n", phead); */
    second=base=0;
    if (max>=4)
    for (i=0; i<PART_MAX; i++) {
/*	print_pt(i+1, pt[i]); */
	if (is_extd_part(pt[i].sys_ind)) {
	    if (!base) base = pt[i].start_sect;
	    else die("invalid partition table: second extended partition found");
	}
	if (where) *where++ = PART_TABLE_OFFSET + i*sizeof(*p);
	*p++ = pt[i];
    }

    max -= (i=4);
    
    if (max>0)
    while (base) {
    	daddr = LLSECTORSIZE*(base+second) + PART_TABLE_OFFSET;
        if (lseek64(fd, daddr, SEEK_SET) < 0)
            die("secondary lseek64 failed");
	if (read(fd, pt, sizeof(pt)) != sizeof(pt)) die("secondary read pt failed");
	if ( read(fd, &boot_sig, sizeof(boot_sig)) != sizeof(boot_sig)  ||
		boot_sig[0] != BOOT_SIGNATURE0 || boot_sig[1] != BOOT_SIGNATURE1 )
			die("read second boot signature failed");
/*	print_pt(i++, pt[0]); */
        if (is_extd_part(pt[1].sys_ind)) second=pt[1].start_sect;
        else base = 0;
        if (max-- > 0) {
	    *p++ = pt[0];
	    if (where) *where++ = daddr;
	    i++;
        }
    }
    if (max > 0) {
	p->sys_ind = 0;
	if (where) *where = 0;
    }
        
    close(fd);
    
    return i;
}

