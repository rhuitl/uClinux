/* bsect.c  -  Boot sector handling */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2007 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#ifdef	_SYS_STATFS_H
#define	_I386_STATFS_H	/* two versions of statfs is not good ... */
#endif

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>

#include "config.h"
#include "lilo.h"
#include "common.h"
#include "raid.h"
#include "cfg.h"
#include "device.h"
#include "geometry.h"
#include "map.h"
#include "temp.h"
#include "partition.h"
#include "boot.h"
#include "bsect.h"
#include "bitmap.h"
#include "probe.h"
#include "loader.h"
#include "edit.h"

#ifdef SHS_PASSWORDS
#include "shs2.h"
#endif
#if defined(LCF_UNIFY) || defined(LCF_BUILTIN)
#define EARLY_MAP
#endif


int boot_dev_nr;

static BOOT_SECTOR bsect,bsect_orig;
static MENUTABLE menuparams;
static DESCR_SECTORS descrs;
static char secondary_map[SECTOR_SIZE];
static unsigned char table[SECTOR_SIZE];	/* keytable & params */
static DEVICE dev;
static char *boot_devnam,*map_name;
static int use_dev_close = 0;
static int fd;
static int image_base = 0,image = 0;
static char temp_map[PATH_MAX+1];
static char *fallback[MAX_IMAGES];
static int fallbacks = 0;
static unsigned short stage_flags;
static int image_menu_space = MAX_IMAGES;
static char *getval_user;
static BOOT_PARAMS_2 param2;
static off_t here2;		/* sector address of second stage loader */
static int adapter = -1;	/* video adapter in use */

typedef struct Pass {
    int crc[MAX_PW_CRC];
    char *unique;
    char *label;
    struct Pass *next;
    } PASSWORD;

static PASSWORD *pwsave = NULL;

BUILTIN_FILE *select_loader(void)
{
    BUILTIN_FILE *loader = &Third;	/* MENU interface is the default */
    char *install = cfg_get_strg(cf_options,"install");
    char *bitmap  = cfg_get_strg(cf_options,"bitmap");

    if (!install) {
	if (bitmap) loader = &Bitmap;
    } 
    else if (strstr(install,"text")) loader = &Second;  /* text interface */
    else if (strstr(install,"menu")) loader = &Third;
    else if (strstr(install,"bmp") || bitmap) loader = &Bitmap;   /* menu interface (MDA, EGA, VGA) */
	
    adapter = get_video();	/* from probe.c */

    if (adapter <= VIDEO_UNKNOWN && (verbose>=2 || loader==&Bitmap))
	    warn("Unable to determine video adapter in use in the present system.");
    if (loader == &Third && adapter == VIDEO_CGA)
	    warn("Video adapter (CGA) is incompatible with the boot loader selected for\n"
	    			"  installation ('install = menu').");
    if (loader == &Bitmap && adapter < VIDEO_MCGA && adapter > VIDEO_UNKNOWN)
	    warn("Video adapter (%s) is incompatible with the boot loader selected for\n"
	    			"  installation ('install = bitmap').", adapter==VIDEO_CGA ? "CGA" :
	    			adapter==VIDEO_MDA ? "MDA" : "unknown");
    
    return loader;
}


/* kludge:  'append="..."' may not contain keywords acted upon by 
   the LILO boot loader -- except "mem=XXX"
 */
#define MEM_OKAY 1
static void check_options(char *options)
{
static char *disallow[] = { 
#if !MEM_OKAY
			"mem=",
#endif
				"vga=", "kbd=", "lock", "nobd", NULL };
    char *here, **dis = disallow;
    int error = 0;

    if (verbose >= 5) printf("check_options: \"%s\"\n", options);
    if (strlen(options) > COMMAND_LINE_SIZE-1) {
	warn("Command line options > %d will be truncated.", COMMAND_LINE_SIZE-1);
    }
    while (*dis) {
	here = strstr(options, *dis);
	if (here  &&  (here==options || here[-1] == ' ') ) {
	    if (here[3] == '=') error=2;
	    if (here[3] != '=' && (here[4]==' ' || here[4]==0) ) error=2;
#if !MEM_OKAY
	    if (*dis == disallow[0] && here[4]>='0' && here[4]<='9')
		error = 1 
		/*	  + (cfg_get_strg(cf_kernel,"initrd") != NULL ||
			     cfg_get_strg(cf_options,"initrd") != NULL) */
			     ;
#endif
	}
	if (error>1) die ("APPEND or LITERAL may not contain \"%s\"", *dis);
#if !MEM_OKAY
	if (error==1) {
	    warn("APPEND or LITERAL may not contain \"mem=\".");
	    error = 0;
	}
#endif
	++dis;
    }    
}

static int getval(char **cp, int low, int high, int default_value, int factor)
{
    int temp;
    
    if (!**cp) {
	if (factor && eflag) {
	    if (low==1) default_value--;
	    default_value *= factor;
	}
    }
    else if (ispunct(**cp)) {
	(*cp)++;
	if (factor && eflag) {
	    if (low==1) default_value--;
	    default_value *= factor;
	}
    } else {
	temp = strtol(*cp, cp, 0);
	if (!factor) default_value = temp;
	else {
	    if (**cp == 'p' || **cp == 'P') {
		(*cp)++;
		default_value = temp;
		temp /= factor;
		if (low==1) temp++;
	    } else {
		default_value = (low==1 ? temp-1 : temp)*factor;
	    }
	}
	
	if (temp < low || temp > high)
		die("%s: value out of range [%d,%d]", getval_user, low, high);
	if (**cp && !ispunct(**cp)) die("Invalid character: \"%c\"", **cp);
	if (**cp) (*cp)++;
    }
    if (verbose>=5) printf("getval: %d\n", default_value);
    
    return default_value;
}

void bmp_do_timer(char *cp, MENUTABLE *menu)
{
    if (!cp) {
	if (eflag) menu->t_row = menu->t_col = -1;  /* there is none, if not specified during edit */
    } else if (strcasecmp(cp,"none")==0) {
	menu->t_row = menu->t_col = -1;  /* there is none, if specified as "none" */
    } else {
	getval_user = "bmp-timer";
    	menu->t_col = getval(&cp, 1, 76, menu->t_col, 8);
    	menu->t_row = getval(&cp, 1, 30, menu->t_row, 16);

    	if (!*cp && !eflag) return;
    	menu->t_fg = getval(&cp, 0, colormax, menu->fg, 0);
    	menu->t_bg = getval(&cp, 0, colormax, eflag?colormax^menu->t_fg:menu->t_bg, 0);
    	menu->t_sh = getval(&cp, 0, colormax, menu->t_fg, 0);
    }
}


void bmp_do_table(char *cp, MENUTABLE *menu)
{
    if (!cp) {
	if (eflag) cp = "";
	else return;		/* dont change anything */
    }
    
    getval_user = "bmp-table";
    menu->col = getval(&cp, 1, 80-MAX_IMAGE_NAME, menu->col/8 + 1, 8);
    menu->row = getval(&cp, 1, 29, menu->row/16 + 1, 16);
#if 0
    menu->ncol = getval(&cp, 1, 80/(MAX_IMAGE_NAME+2), 1, 0);
    menu->maxcol = getval(&cp, 3, MAX_IMAGES, (MAX_IMAGES+menu->ncol-1)/menu->ncol, 0);
    menu->xpitch = getval(&cp, MAX_IMAGE_NAME+2, 80/menu->ncol, MAX_IMAGE_NAME+6, 8);
#else
    menu->ncol = getval(&cp, 1, 80/(MAX_IMAGE_NAME+1), menu->ncol, 0);
    menu->maxcol = getval(&cp, 2, 30 - menu->row/16, eflag?30 - menu->row/16:menu->maxcol, 0);
    menu->xpitch = getval(&cp, MAX_IMAGE_NAME+1, menu->ncol==1?80-menu->col/8:(80-menu->col/8-MAX_IMAGE_NAME*menu->ncol)/(menu->ncol-1)+MAX_IMAGE_NAME, menu->xpitch/8, 8);
    menu->mincol = getval(&cp, 1, menu->maxcol, menu->mincol, 0);
#endif
    if ((menu->row + menu->maxcol*16 > 480 || 
	 menu->col + (MAX_IMAGE_NAME+1)*8 + (menu->ncol-1)*menu->xpitch > 640))  
	         warn("'bmp-table' may spill off screen");
}


void bmp_do_colors(char *cp, MENUTABLE *menu)
{
    if (!cp) {
	if (eflag) cp = "";
	else return;		/* dont change anything */
    }

    getval_user = "bmp-colors";
    menu->fg = getval(&cp, 0, colormax, menu->fg, 0);
    if (!*cp && !eflag) return;
    menu->bg = getval(&cp, 0, colormax, menu->fg, 0);
    menu->sh = getval(&cp, 0, colormax, menu->fg, 0);

    menu->h_fg = getval(&cp, 0, colormax, menu->h_fg, 0);
    if (!*cp && !eflag) return;
    menu->h_bg = getval(&cp, 0, colormax, menu->h_fg, 0);
    menu->h_sh = getval(&cp, 0, colormax, menu->h_fg, 0);    	
}

void pw_file_update(int passw)
{
    PASSWORD *walk;
    int i;
    
    if (verbose>=4) printf("pw_file_update:  passw=%d\n", passw);

    if (passw && !test && pw_file) {
	if (fseek(pw_file,0L,SEEK_SET)) perror("pw_file_update");
    
	for (walk=pwsave; walk; walk=walk->next) {
	    fprintf(pw_file, "label=<\"%s\">", walk->label);
	    for (i=0; i<MAX_PW_CRC; i++) fprintf(pw_file, " 0x%08X", walk->crc[i]);
	    fprintf(pw_file, "\n");
	}
    }
    if (pw_file) fclose(pw_file);
}

void pw_fill_cache(void)
{
    char line[MAX_TOKEN+1];
    char *brace;
    char *label;
    PASSWORD *new;
    int i;
     
    if (verbose>=5) printf("pw_fill_cache\n");    
    if (fseek(pw_file,0L,SEEK_SET)) perror("pw_fill_cache");
    
    while (fgets(line,MAX_TOKEN,pw_file)) {
    	if (verbose>=5) printf("   %s\n", line);
    	brace = strrchr(line,'>');
    	label = strchr(line,'<');
    	if (label && label[1]=='"' && brace && brace[-1]=='"') {
	    brace[-1] = 0;
	    if ( !(new = alloc_t(PASSWORD)) ) pdie("Out of memory");
	    new->next = pwsave;
	    pwsave = new;
	    new->unique = NULL;
	    new->label = stralloc(label+2);
	    if (verbose>=2) printf("Password file: label=%s\n", new->label);
	    brace++;
    	    for (i=0; i<MAX_PW_CRC; i++) {
		new->crc[i] = strtoul(brace,&label,0);
		brace = label;
    	    }
    	}
    	else die("Ill-formed line in .crc file");
    }
    if (verbose >=5) printf("end pw_fill_cache\n");
}

static void hash_password(char *password, int crcval[])
{
#ifdef CRC_PASSWORDS
   static int poly[] = {CRC_POLY1, CRC_POLY2, CRC_POLY3, CRC_POLY4, CRC_POLY5};
#endif
	int crc;
	int j;
	int i = strlen(password);
	
#ifdef SHS_PASSWORDS
	shsInit();
	shsUpdate((BYTE*)password, i);
	shsFinal();
#endif
	for (j=0; j<MAX_PW_CRC; j++) {
	    crcval[j] = crc =
#ifdef CRC_PASSWORDS
	    			crc32((unsigned char *)password, i, poly[j]);
  #define PWTYPE "CRC-32"
#else
				shsInfo.digest[j];
  #define PWTYPE "SHS-160"
#endif
	    if(verbose >= 2) {
		if (j==0) printf("Password " PWTYPE " =");
		printf(" %08X", crc);
	    }
	}
	if (verbose >= 2) printf("\n");
}


void pw_wipe(char *pass)
{
    int i;
    
    if (!pass) return;
    i = strlen(pass);
    while (i) pass[--i]=0;
    free(pass);
}


char *pw_input(void)
#if 1
{
    char *cp = getpass("");
    int i = strlen(cp);
    char *acp = stralloc(cp);

    while (i) cp[i--] = 0;
    return acp;    
}
#else
{
    char *pass;
    char buf[MAX_TOKEN+1];
    int i, ch;
    
    i = 0;
    fflush(stdout);
    while((ch=getchar())!='\n') if (i<MAX_TOKEN) buf[i++]=ch;
    buf[i]=0;
    pass = stralloc(buf);
    while (i) buf[--i]=0;
    return pass;
}
#endif

static void pw_get(char *pass, int crcval[], int option)
{
    PASSWORD *walk;
    char *pass2;
    char *label;
    
    label = cfg_get_strg(cf_all, "label");
    if (!label) label = cfg_get_strg(cf_top, "image");
    if (!label) label = cfg_get_strg(cf_top, "other");
    if (!label) die("Need label to get password");
    if ((pass2 = strrchr(pass,'/'))) label = pass2+1;

    for (walk=pwsave; walk; walk=walk->next) {
	if (pass == walk->unique ||
		(!walk->unique && !strcmp(walk->label,label) && (walk->unique=pass)) ) {
	    memcpy(crcval, walk->crc, MAX_PW_CRC*sizeof(int));
	    return;
	}
    }
    walk = alloc_t(PASSWORD);
    if (!walk) die("Out of memory");
    walk->next = pwsave;
    pwsave = walk;
    walk->unique = pass;
    walk->label = stralloc(label);
    
    printf("\nEntry for  %s  used null password\n", label);
    pass = pass2 = NULL;
    do {
    	if (pass) {
    	    printf("   *** Phrases don't match ***\n");
    	    pw_wipe(pass);
    	    pw_wipe(pass2);
	}
	printf("Type passphrase: ");
	pass2 = pw_input();
	printf("Please re-enter: ");
	pass = pw_input();
    } while (strcmp(pass,pass2));
    printf("\n");
    pw_wipe(pass2);  
    hash_password(pass, walk->crc);
    pw_wipe(pass);
    memcpy(crcval, walk->crc, MAX_PW_CRC*sizeof(int));
}


static void retrieve_crc(int crcval[])
{
    int i;
    char *pass;
    
    if (!pwsave) {
	if (cfg_pw_open()) pw_fill_cache();
    }
    pass = cfg_get_strg(cf_all,"password");
    if (pass) pw_get(pass,crcval,0);
    else pw_get(cfg_get_strg(cf_options,"password"),crcval,1);

    if (verbose >= 2) {
	printf("Password found is");
	for (i=0; i<MAX_PW_CRC; i++) printf(" %08X", crcval[i]);
	printf("\n");
    }
}



static void open_bsect(char *boot_dev)
{
    struct stat st;

    if (verbose > 0)
	printf("Reading boot sector from %s\n",boot_dev ? boot_dev :
	  "current root.");
    boot_devnam = boot_dev;
    if (!boot_dev || !strcmp(boot_dev, "/") ) {
	if (stat("/",&st) < 0) pdie("stat /");
	if (MAJOR(st.st_dev) != MAJOR_MD &&
		(st.st_dev & P_MASK(st.st_dev)) > PART_MAX)
	    die("Can't put the boot sector on logical partition 0x%04X",
	      (int)st.st_dev);
	fd = dev_open(&dev,boot_dev_nr = st.st_dev,O_RDWR);
	boot_devnam = dev.name;
	use_dev_close = 1;
    }
    else {
	if ((fd = open(boot_dev,O_RDWR)) < 0)
	    die("open %s: %s",boot_dev,strerror(errno));
	if (fstat(fd,&st) < 0) die("stat %s: %s",boot_dev,strerror(errno));
	if (!S_ISBLK(st.st_mode)) boot_dev_nr = 0;
	else boot_dev_nr = st.st_rdev;
    }
/* new code to get boot device code */
/* plus geo_open will trigger VolumeMgmt (pf_hard_disk_scan) before the
   boot sector is actually read; timing is very important */
{
    GEOMETRY geo;
    geo_open(&geo, boot_devnam, O_RDONLY);
    bios_boot = geo.device;
    geo_close(&geo);
}
    
    if (boot_dev_nr && !is_first(boot_dev_nr) )
	warn("%s is not on the first disk",boot_dev ?
	  boot_dev : "current root");
    if (read(fd,(char *) &bsect,SECTOR_SIZE) != SECTOR_SIZE)
	die("read %s: %s",boot_dev ? boot_dev : dev.name,strerror(errno));
    bsect_orig = bsect;
    ireloc = part_nowrite(boot_devnam);
    if (ireloc == PTW_DOS + PTW_NTFS)  ireloc = PTW_DOS;
/* check for override (-F) command line flag */
    if (ireloc>PTW_DOS && force_fs) {
        int nowarn2 = nowarn;
        nowarn = 0;

	warn("'-F' override used. Filesystem on  %s  may be destroyed.", boot_devnam);
	if (!yesno("\nProceed? ",0)) exit(0);

        nowarn = nowarn2;
	ireloc=PTW_OKAY;
    }
}


void bsect_read(char *boot_dev,BOOT_SECTOR *buffer)
{
    open_bsect(boot_dev);
    *buffer = bsect;
    (void) close(fd);
}


static void menu_do_scheme(char *scheme, MENUTABLE *menu)
{
    static char khar[] = "kbgcrmywKBGCRMYW";
    unsigned int fg, bg;
    int i;
    unsigned char *at;
    /* order of color attributes is:
	  text, hilighted text, border, title
    */
#define color(c) ((int)(strchr(khar,(int)(c))-khar))
    bg = 0;
    at = &(menu->at_text);
    for (i=0; i<4 && *scheme; i++) {
    	fg = color(*scheme);
    	if (fg>=16) die("Invalid menu-scheme color: '%c'", *scheme);
    	if (*++scheme) bg = color(*scheme);
    	else {
	    die("Invalid menu-scheme syntax");
    	}
    	if (bg>=16) die("Invalid menu-scheme color: '%c'", *scheme);
    	if (*++scheme) {
    	    if (ispunct(*scheme)) scheme++;
    	    else die("Invalid menu-scheme punctuation");
    	}
    	if (bg>=8)
    	    warn("menu-scheme BG color may not be intensified");
    	*at++ = ((bg<<4) | fg) & 0x7F;
    }
    /* check on the TEXT color */
    if (menu->at_text == 0) {
        warn("menu-scheme \"black on black\" changed to \"white on black\"");
	menu->at_text = 0x07;
    }
    /* check on the HIGHLIGHT color */
    if (menu->at_highlight == 0)  menu->at_highlight = ((menu->at_text<<4)&0x70) | ((menu->at_text>>4)&0x0f);
    /* check on the BORDER color */
    if (menu->at_border == 0)  menu->at_border = menu->at_text;
    /* check on the TITLE color */
    if (menu->at_title == 0)  menu->at_title = menu->at_border;
    
    strncpy(menu->menu_sig, "MENU", 4);
    if (verbose>=5)
       printf("Menu attributes: text %02X  highlight %02X  border %02X  title %02X\n",
       		(int)menu->at_text, (int)menu->at_highlight,
       		(int)menu->at_border, (int)menu->at_title);
#undef color
}


void bsect_open(char *boot_dev,char *map_file,char *install,int delay,
  int timeout, int raid_offset)
{
    static char coms[] = "0123";
    static char parity[] = "NnOoEe";
    static char bps[] = 
	"110\000150\000300\000600\0001200\0002400\0004800\0009600\000"
	"19200\00038400\00057600\000115200\000?\000?\000?\000?\000"
	"56000\000";
    GEOMETRY geo;
    struct stat st;
    int i, speed, bitmap, j, dataend;
    int m_fd=0,kt_fd,sectors;
    char *message,*colon,*serial,*walk,*this,*keytable,*scheme;
    MENUTABLE *menu;
    BITMAPFILEHEADER fhv;
    BITMAPHEADER bmhv;
    BITMAPLILOHEADER lhv;
    unsigned int timestamp;
#ifdef LCF_BUILTIN
    BUILTIN_FILE *loader;
#else
    int i_fd;
#endif

#if 0
printf("sizeof(IMAGE_DESCR) = %d\n", sizeof(IMAGE_DESCR));
printf("sizeof(DESCR_SECTORS) = %d\n", sizeof(DESCR_SECTORS));
printf("MAX_IMAGES = %d\n", MAX_IMAGES);
#endif
    image = image_base = i = 0;
    memset(&menuparams, 0, sizeof(menuparams));
    if (stat(map_file,&st) >= 0 && !S_ISREG(st.st_mode))
	die("Map %s is not a regular file.",map_file);
    open_bsect(boot_dev);
    part_verify(boot_dev_nr,1);
    if (ireloc>PTW_DOS) {
    	die("Filesystem would be destroyed by LILO boot sector: %s", boot_dev);
    }
    else if (ireloc==PTW_DOS) {
	warn("boot record relocation beyond BPB is necessary: %s", boot_dev);
    }

#ifdef EARLY_MAP
    if ((colon = strrchr(map_name = map_file,':')) == NULL)
	strcat(strcpy(temp_map,map_name),MAP_TMP_APP);
    else {
	*colon = 0;
	strcat(strcat(strcpy(temp_map,map_name),MAP_TMP_APP),colon+1);
	*colon = ':';
    }
    map_create(temp_map);
    temp_register(temp_map);
#endif

    if (!install) {
#if !defined(LCF_NOINSTDEF) || defined(LCF_BUILTIN)
	install = DFL_BOOT;
#else
	die("No boot loader specified ('-i' or 'install =')");
#endif
    } 
/*  if (install) */ {
	timestamp = bsect.par_1.timestamp; /* preserve timestamp */

/* determine which secondary loader to use */

	loader = select_loader();
	if (verbose > 0) {
	    printf("Using %s secondary loader\n",
		loader==&Bitmap ? "BITMAP" :
		loader==&Third  ? "MENU" :
		"TEXT" );
	}
	memcpy(&bsect, First.data, MAX_BOOT_SIZE);

	bsect.par_1.timestamp = timestamp;
	map_begin_section(); /* no access to the (not yet open) map file
		required, because this map is built in memory */
	here2 = map_insert_data (loader->data, loader->size);
	memcpy(&param2,loader->data,sizeof(param2));
#ifdef LCF_FIRST6
	/* write just the 4 bytes (sa6==2) */
	sectors = map_write((SECTOR_ADDR*)secondary_map, (SECTOR_SIZE-4)/sizeof(SECTOR_ADDR)-2, 1, 2);
#else
	sectors = map_write((SECTOR_ADDR*)secondary_map, (SECTOR_SIZE-4)/sizeof(SECTOR_ADDR)-2, 1);
#endif
	memcpy(secondary_map+SECTOR_SIZE-4, EX_MAG_STRING, 4);

	/* fill in full size of secondary boot loader in paragraphs */
	/*bsect.par_1.*/dataend = (sectors + 5 + (COMMAND_LINE_SIZE>256) + MAX_DESCR_SECS) * (SECTOR_SIZE/16);

	if (verbose > 1)
	    printf("Secondary loader: %d sector%s (0x%0X dataend).\n",sectors,sectors == 1 ?
	      "" : "s", /*bsect.par_1.*/dataend*16);
	stage_flags = ((BOOT_SECTOR*)(loader->data)) -> par_2.stage;
	if ((stage_flags & 0xFF) != STAGE_SECOND)
	    die("Ill-formed boot loader; no second stage section");

	if (verbose>=4) printf("install(2) flags: 0x%04X\n", (int)stage_flags);
    }

#ifndef EARLY_MAP
    if ((colon = strrchr(map_name = map_file,':')) == NULL)
	strcat(strcpy(temp_map,map_name),MAP_TMP_APP);
    else {
	*colon = 0;
	strcat(strcat(strcpy(temp_map,map_name),MAP_TMP_APP),colon+1);
	*colon = ':';
    }
    map_create(temp_map);
    temp_register(temp_map);
#endif

	map_begin_section();
	map_add_sector(secondary_map);
#ifdef LCF_FIRST6
	/* write out six byte address */
	(void) map_write(&bsect.par_1.secondary,1,0,1);
#else
	(void) map_write(&bsect.par_1.secondary,1,0);
#endif

/* if the state of the BIOS is DL_GOOD, always mark when boot==map
   if the state of the BIOS is < DL_GOOD, never mark */
   
	if ( bios_boot == bios_map  &&
		(bios_passes_dl == DL_GOOD
		 || (do_md_install && !(extra==X_MBR_ONLY ))
		  ) )
	    bsect.par_1.prompt |= FLAG_MAP_ON_BOOT;
	if (bios_boot!=bios_map)
	    warn("The boot sector and map file are on different disks.");
	if ( (bios_map & 0x80) && !do_md_install &&
		!cfg_get_flag(cf_options, "static-bios-codes") ) /* hard disk & not raid master */
	    bsect.par_1.map_serial_no = serial_no[bios_map - 0x80];
	if (verbose>=2)
	    printf("bios_boot = 0x%02X  bios_map = 0x%02X  map==boot = %d  map S/N: %08X\n",
		bios_boot, bios_map,
		!!(bsect.par_1.prompt&FLAG_MAP_ON_BOOT),
		bsect.par_1.map_serial_no);
    
/* code to get creation time of map file */
    if (stat(temp_map, &st) < 0) die("Cannot get map file status");
    param2.map_stamp = bsect.par_1.map_stamp = st.st_mtime;
    if (verbose>=4) printf("Map time stamp: %08X\n", (int)bsect.par_1.map_stamp);

    bsect.sector[BOOT_SIG_OFFSET] = BOOT_SIGNATURE0;
    bsect.sector[BOOT_SIG_OFFSET+1] = BOOT_SIGNATURE1;
    message = cfg_get_strg(cf_options,"message");
    scheme = cfg_get_strg(cf_options,"bitmap");
    if (message && scheme) die("'bitmap' and 'message' are mutually exclusive");
    param2.msg_len = 0;
    bitmap = (loader==&Bitmap);
    if (bitmap) {
	message = scheme;
	if (!(stage_flags & STAGE_FLAG_BMP4)) {
	    warn("Non-bitmap capable boot loader; 'bitmap=' ignored.");
	    message = NULL;
	}
    }
    j = -1;
    if (message) {
	if (verbose >= 1) {
	    printf("Mapping %s file %s", 
			bitmap ? "bitmap" : "message", message);
	    show_link(message);
	    printf("\n");
	}
	m_fd = geo_open(&geo,message,O_RDONLY);
	if (fstat(m_fd,&st) < 0) die("stat %s: %s",message,strerror(errno));
	/* the -2 below is because of GCC's alignment requirements */
	i = sizeof(BITMAPFILEHEADER)+sizeof(BITMAPHEADER)+sizeof(RGB)*16+
				sizeof(BITMAPLILOHEADER);
	if (bitmap || st.st_size>i) {
	    int bits=0;
	    
	    j = get_std_headers(m_fd, &fhv, &bmhv, &lhv);
	    if (j<0) die("read %s: %s", message, strerror(errno));
	    if (j==0 || j>2) { /* definitely a bitmap file */
		BITMAPHEADER *bmh = &bmhv;
		if (verbose >= 3) {
		    printf("width=%d height=%d planes=%d bits/plane=%d\n",
			(int)bmh->width, (int)bmh->height,
			(int)bmh->numBitPlanes, (int)bmh->numBitsPerPlane);
		}
		if (bmh->size == sizeof(BITMAPHEADER) &&
			bmh->width==640 && bmh->height==480 && 
		    	((bits = bmh->numBitPlanes * bmh->numBitsPerPlane) == 4 ||
		    	  bits == 8) ) {
		    if (!bitmap) die("Message specifies a bitmap file");
		    if (bits>4 && adapter<VIDEO_VESA)
			warn("Video adapter does not support VESA BIOS extensions needed for\n"
				       "  display of 256 colors.  Boot loader will fall back to TEXT only operation.");
		}
		else if (bitmap) die("Unsupported bitmap");
	    } else if (bitmap) die("Not a bitmap file");
	}
	i = bitmap ? MAX_KERNEL_SECS*SECTOR_SIZE : MAX_MESSAGE;
	if (st.st_size > i)
	    die("%s is too big (> %d bytes)",message,i);
	param2.msg_len = bitmap ? (st.st_size+15)/16 : st.st_size;
	map_begin_section();
#ifndef LCF_UNIFY
	map_add(&geo,0,((st.st_size)+SECTOR_SIZE-1)/SECTOR_SIZE);
#else
	map_insert_file (&geo,0,(st.st_size+SECTOR_SIZE-1)/SECTOR_SIZE);
#endif
	sectors = map_end_section(&menuparams.msg,0);
	if (verbose >= 2)
	    printf("%s: %d sector%s.\n",bitmap?"Bitmap":"Message",
	    		sectors,sectors == 1 ?  "" : "s");
	geo_close(&geo);
    }

    if (cfg_get_flag(cf_options,"el-torito-bootable-cd"))
	param2.flag2 |= FLAG2_EL_TORITO;
    if (cfg_get_flag(cf_options,"unattended")) {
	param2.flag2 |= FLAG2_UNATTENDED;
	if (timeout < 0) {
	    warn("UNATTENDED used; setting TIMEOUT to 20s (seconds).");
	    timeout = 200;
	}
    }
        
    serial = cfg_get_strg(cf_options,"serial");
    if (serial) {
    	if (!(stage_flags & STAGE_FLAG_SERIAL))
    	    die("Serial line not supported by boot loader");
	if (!*serial || !(this = strchr(coms,*serial)))
	    die("Invalid serial port in \"%s\" (should be 0-3)",serial);
	else param2.port = (this-coms)+1;
	param2.ser_param = SER_DFL_PRM;
	if (serial[1]) {
	    if (serial[1] != ',')
		die("Serial syntax is <port>[,<bps>[<parity>[<bits>]]]");
	    walk = bps;
	    speed = 0;
	    while (*walk && strncmp(serial+2,walk,(i=strlen(walk)))) {
		speed++;
		walk += i+1;
	    }
	    if (!*walk) die("Unsupported baud rate");
	    param2.ser_param &= ~0xE4;
	    if (speed==16) speed -= 6;  /* convert 56000 to 57600 */
	    param2.ser_param |= ((speed<<5) | (speed>>1)) & 0xE4;
	    serial += i+2;
	/* check for parity specified */
	    if (*serial) {
		if (!(this = strchr(parity,*serial)))
		    die("Serial speed = %s; valid parity values are N, O and E", walk);
		i = (int)(this-parity)>>1;
		if (i==2) i++; /* N=00, O=01, E=11 */
		param2.ser_param &= ~(i&1); /* 7 bits if parity specified */
		param2.ser_param |= i<<3;   /* specify parity */
	/* check if number of bits is there */
		if (serial[1]) {
		    if (serial[1] != '7' && serial[1] != '8')
			die("Only 7 or 8 bits supported");
		    if (serial[1]=='7')	param2.ser_param &= 0xFE;
		    else param2.ser_param |= 0x01;
		    
		    if (serial[2]) die("Synax error in SERIAL");
		}
	    }
	    if (verbose>=4) printf("Serial Param = 0x%02X\n", 
						(int)param2.ser_param);
	}
	if (delay < 20 && !cfg_get_flag(cf_options,"prompt")) {
	    warn("no PROMPT with SERIAL; setting DELAY to 20 (2 seconds)");
	    delay = 20;
	}
    }
    bsect.par_1.prompt |= cfg_get_flag(cf_options,"prompt") ? FLAG_PROMPT : 0;
    if (cfg_get_flag(cf_options,"suppress-boot-time-BIOS-data")) {
    	warn("boot-time BIOS data will not be saved.");
    	bsect.par_1.prompt |= FLAG_NOBD;
    }
    if (!fetch() && (bios_map &
#if VERSION_MINOR>=50
    			bios_boot &	/* if 'boot=/dev/fd0', force write */
#endif
    				0x80)) {
	bsect.par_1.prompt |= FLAG_BD_OKAY;
	if (verbose>=2) printf("BIOS data check was okay on the last boot\n");
    }
    else {
	if (verbose>=2) printf("BIOS data check will include auto-suppress check\n");
    }
    if (cfg_get_flag(cf_options,"large-memory")) {
#ifndef LCF_INITRDLOW
	bsect.par_1.prompt |= FLAG_LARGEMEM;
#else
	warn("This LILO compiled with INITRDLOW option, 'large-memory' ignored.");
#endif
    }
    bsect.par_1.prompt |= raid_flags;
    bsect.par_1.raid_offset = raid_offset;  /* to be modified in bsect_raid_update */
/* convert timeout in tenths of a second to clock ticks    */
/* tick interval is 54.925 ms  */
/*   54.925 * 40 -> 2197       */
/*  100 * 40 -> 4000	       */
#if 0
#define	tick(x) ((x)*100/55)
#else
#define tick(x) ((x)*4000/2197)
#endif
    delay =  delay==36000 ? 0xffff : tick(delay);
    if (delay > 0xffff) die("Maximum delay is 59:59 (3599.5secs).");
	else param2.delay = delay;

    timeout =  timeout==36000 ? 0xfffe : tick(timeout);	/* -1 -> -1 ticks */
    if (timeout == -1) param2.timeout = 0xffff;
    else if (timeout >= 0xffff) die("Maximum timeout is 59:59 (3599.5secs).");
	else param2.timeout = timeout;

/* keytable & parameter area setup */

    if (!(keytable = cfg_get_strg(cf_options,"keytable"))) {
	for (i = 0; i < 256; i++) table[i] = i;
    }
    else {
	if ((kt_fd = open(keytable,O_RDONLY)) < 0)
	    die("open %s: %s",keytable,strerror(errno));
	if (read(kt_fd,table,256) != 256)
	    die("%s: bad keyboard translation table",keytable);
	(void) close(kt_fd);
    }
#if 0
    menu = (MENUTABLE*)&table[256];
    memset(menu, 0, 256);
#else
    menu = &menuparams;
#endif
    memcpy(&(menu->row), &(lhv.row), sizeof(lhv) - sizeof(lhv.size) - sizeof(lhv.magic));

    if ((scheme = cfg_get_strg(cf_options,"menu-scheme"))) {
	if (!(stage_flags & STAGE_FLAG_MENU))
	    warn("'menu-scheme' not supported by boot loader");
    	menu_do_scheme(scheme, menu);
    }
    if ((scheme = cfg_get_strg(cf_options,"menu-title"))) {
	if (!(stage_flags & STAGE_FLAG_MENU))
	    warn("'menu-title' not supported by boot loader");
	if (strlen(scheme) > MAX_MENU_TITLE)
	    warn("menu-title is > %d characters", MAX_MENU_TITLE);
    	strncpy(menu->title, scheme, MAX_MENU_TITLE);
    	menu->len_title = strlen(menu->title);
    }
    if ((scheme = cfg_get_strg(cf_options,"bmp-table"))) {
	if (!(stage_flags & STAGE_FLAG_BMP4))
	    warn("'bmp-table' not supported by boot loader");
    }
    bmp_do_table(scheme, menu);
    if (bitmap) {
	image_menu_space = menu->ncol * menu->maxcol;
	if (verbose>=3) printf("image_menu_space = %d\n", image_menu_space);
    }
    if ((scheme = cfg_get_strg(cf_options,"bmp-colors"))) {
	if (!(stage_flags & STAGE_FLAG_BMP4))
	    warn("'bmp-colors' not supported by boot loader");
    }
    bmp_do_colors(scheme, menu);
    if ((scheme = cfg_get_strg(cf_options,"bmp-timer"))) {
	if (!(stage_flags & STAGE_FLAG_BMP4))
	    warn("'bmp-timer' not supported by boot loader");
    }
    bmp_do_timer(scheme, menu);
#if 0
    map_begin_section();
    map_add_sector(table);
    (void) map_write(&param2.keytab,1,0);
#endif
    memset(&descrs,0,SECTOR_SIZE*MAX_DESCR_SECS);
    if (cfg_get_strg(cf_options,"default")) image = image_base = 1;
    if (verbose > 0) printf("\n");
}


static int dev_number(char *dev)
{
    struct stat st;

    if (stat(dev,&st) >= 0) return st.st_rdev;
    if (!isdigit(*dev)) die("Illegal 'root=' specification: %s", dev);
    if (verbose >= 1) 
	printf("Warning: cannot 'stat' device \"%s\"; trying numerical conversion\n", dev);
    return to_number(dev);
}


static int get_image(char *name,char *label,IMAGE_DESCR *descr)
{
    char *here,*deflt;
    int this_image,other;
    unsigned char *uch;

    if (!label) {
	here = strrchr(label = name,'/');
	if (here) label = here+1;
    }
    if (strchr(label,' ')) die("Image name, label, or alias contains a blank character: '%s'", label);
    if (strlen(label) > MAX_IMAGE_NAME) die("Image name, label, or alias is too long: '%s'",label);
    for (uch=(unsigned char*)label; *uch; uch++) {
	if (*uch<' ')  die("Image name, label, or alias contains an illegal character: '%s'", label);
    }
    for (other = image_base; other <= image; other++) {
#ifdef LCF_IGNORECASE
	if (!strcasecmp(label,descrs.d.descr[other].name))
#else
	if (!strcmp(label,descrs.d.descr[other].name))
#endif
	    die("Duplicate label \"%s\"",label);
	if ((((descr->flags & FLAG_SINGLE) && strlen(label) == 1) ||
	  (((descrs.d.descr[other].flags) & FLAG_SINGLE) &&
	  strlen(descrs.d.descr[other].name) == 1)) &&
#ifdef LCF_IGNORECASE
	  toupper(*label) == toupper(*descrs.d.descr[other].name))
#else
	  *label == *descrs.d.descr[other].name)
#endif
	    die("Single-key clash: \"%s\" vs. \"%s\"",label,
	      descrs.d.descr[other].name);
    }

    if (image_base && (deflt = cfg_get_strg(cf_options,"default")) &&
#ifdef LCF_IGNORECASE
      !strcasecmp(deflt,label))
#else
      !strcmp(deflt,label))
#endif
	this_image = image_base = 0;
    else {
	if (image == MAX_IMAGES)
	    die("Only %d image names can be defined",MAX_IMAGES);
	if (image >= image_menu_space)
	    die("Bitmap table has space for only %d images",
	    			image_menu_space);
	this_image = image++;
    }
    descrs.d.descr[this_image] = *descr;
    strcpy(descrs.d.descr[this_image].name,label);

#ifdef LCF_VIRTUAL
    if ( (deflt = cfg_get_strg(cf_options,"vmdefault")) &&
#ifdef LCF_IGNORECASE
		!strcasecmp(deflt,label))  {
#else
		!strcmp(deflt,label))  {
#endif
	descrs.d.descr[this_image].flags |= FLAG_VMDEFAULT;
	param2.flag2 |= FLAG2_VIRTUAL;
	}
#endif

#ifdef LCF_NOKEYBOARD
    if ( (deflt = cfg_get_strg(cf_options,"nokbdefault")) &&
#ifdef LCF_IGNORECASE
		!strcasecmp(deflt,label))  {
#else
		!strcmp(deflt,label))  {
#endif
	descrs.d.descr[this_image].flags |= FLAG_NOKBDEFAULT;
	param2.flag2 |= FLAG2_NOKBD;
	}
#endif

    return this_image;
}


static char options[SECTOR_SIZE]; /* this is ugly */


static void bsect_common(IMAGE_DESCR *descr, int image)
{
    struct stat st;
    char *here,*root,*ram_disk,*vga,*password;
    char *literal,*append,*fback;
    char fallback_buf[SECTOR_SIZE];

    memset(descr, 0, sizeof(IMAGE_DESCR));	/* allocated on stack by caller */
    memset(fallback_buf,0,SECTOR_SIZE);
    memset(options,0,SECTOR_SIZE);
    
if (image) { /* long section specific to 'image=' */
    char *append_local;
    
    if ((cfg_get_flag(cf_kernel,"read-only") && cfg_get_flag(cf_kernel,
      "read-write")) || (cfg_get_flag(cf_options,"read-only") && cfg_get_flag(
      cf_options,"read-write")))
	die("Conflicting READONLY and READ_WRITE settings.");

    if (cfg_get_flag(cf_kernel,"read-only") || cfg_get_flag(cf_options,
      "read-only")) strcat(options,"ro ");
    if (cfg_get_flag(cf_kernel,"read-write") || cfg_get_flag(cf_options,
      "read-write")) strcat(options,"rw ");
    if ((root = cfg_get_strg(cf_kernel,"root")) || (root = cfg_get_strg(
      cf_options,"root")))  {
	if (!strcasecmp(root,"current")) {
	    if (stat("/",&st) < 0) pdie("stat /");
	    sprintf(strchr(options,0),"root=%x ",(unsigned int) st.st_dev);
	}
	else if (strlen(root)>6 && !strncmp(root,"LABEL=",6)) {
	    sprintf(strchr(options,0),"root=%s ", root);
	}
        else if (strlen(root)>5 && !strncmp(root,"UUID=",5)) {
            sprintf(strchr(options,0),"root=%s ", root);
        }
	else {
	    sprintf(strchr(options,0),"root=%x ",dev_number(root));
	}
      }	
    if ((ram_disk = cfg_get_strg(cf_kernel,"ramdisk")) || (ram_disk =
      cfg_get_strg(cf_options,"ramdisk")))
	sprintf(strchr(options,0),"ramdisk=%d ",to_number(ram_disk));

    if ((vga = cfg_get_strg(cf_kernel,"vga")) || (vga = cfg_get_strg(cf_options,
      "vga"))) {
#ifndef NORMAL_VGA
	warn("VGA mode presetting is not supported; ignoring 'vga='");
#else
	descr->flags |= FLAG_VGA;
	     if (!strcasecmp(vga,"normal")) descr->vga_mode = NORMAL_VGA;
	else if (!strcasecmp(vga,"ext") || !strcasecmp(vga,"extended"))
		descr->vga_mode = EXTENDED_VGA;
	else if (!strcasecmp(vga,"ask")) descr->vga_mode = ASK_VGA;
	else descr->vga_mode = to_number(vga);
#endif
    }

#ifdef LCF_BOOT_FILE
    if ((append = cfg_get_strg(cf_top, "image"))) {
	strcat(options, "BOOT_FILE=");
	strcat(options, append);
	strcat(options, " ");
    }
#endif
    append_local = cfg_get_strg(cf_options,"append");	/* global, actually */
    if ((append = cfg_get_strg(cf_kernel,"append")) ||
	(append = append_local)  ) {
		if (strlen(append) > COMMAND_LINE_SIZE-1) die("Command line options > %d", COMMAND_LINE_SIZE-1);
		strcat(strcat(options,append)," ");
    }

#if 1
    append = append_local;	/* append == global append */
    if ((append_local = cfg_get_strg(cf_kernel,"addappend"))) {
	if (!append)
	    warn("ADDAPPEND used without global APPEND");
	if (strlen(options)+strlen(append_local) > SECTOR_SIZE-1) die("Command line options > %d", COMMAND_LINE_SIZE-1);
	strcat(options,append_local);
    }
#endif

} /* end of section specific to 'image=' */

    literal = cfg_get_strg(cf_kernel,"literal");
    if (literal) strcpy(options,literal);
    if (*options) {
	here = strchr(options,0);
	if (here[-1] == ' ') here[-1] = 0;
    }
    check_options(options);

    if (cfg_get_flag(cf_kernel,"lock") || cfg_get_flag(cf_options,"lock")) {
#ifdef LCF_READONLY
	die("This LILO is compiled READONLY and doesn't support the LOCK "
	  "option");
#else
	descr->flags |= FLAG_LOCK;
#endif
    }

    if ((cfg_get_flag(cf_options,"restricted") && 
	     cfg_get_flag(cf_options,"mandatory")) ||
	(cfg_get_flag(cf_all,"restricted") && 
	     cfg_get_flag(cf_all,"mandatory")))
	 die("MANDATORY and RESTRICTED are mutually exclusive");
    if (cfg_get_flag(cf_all,"bypass")) {
	if (cfg_get_flag(cf_all,"mandatory"))
	     die("MANDATORY and BYPASS are mutually exclusive");
	if (cfg_get_flag(cf_all,"restricted"))
	     die("RESTRICTED and BYPASS are mutually exclusive");
	if (!cfg_get_strg(cf_options,"password"))
	     die("BYPASS only valid if global PASSWORD is set");
    }
    if ((password = cfg_get_strg(cf_all,"password")) && cfg_get_flag(cf_all,"bypass"))
	die("PASSWORD and BYPASS not valid together");
    if (password || 
	( (password = cfg_get_strg(cf_options,"password")) &&
	  !cfg_get_flag(cf_all,"bypass")  ) ) {
	if (!*password) {	/* null password triggers interaction */
	    retrieve_crc((int*)descr->password_crc);
	} else {
	    hash_password(password, (int*)descr->password_crc );
	}
	descr->flags |= FLAG_PASSWORD;
    }

#ifdef LCF_VIRTUAL
    if (cfg_get_flag(cf_all,"vmwarn")) {
        descr->flags |= FLAG_VMWARN;
	param2.flag2 |= FLAG2_VIRTUAL;
    }
    if (cfg_get_flag(cf_all,"vmdisable")) {
        descr->flags |= FLAG_VMDISABLE;
	param2.flag2 |= FLAG2_VIRTUAL;
    }
    if ( (descr->flags & FLAG_VMWARN) && (descr->flags & FLAG_VMDISABLE) )
	die ("VMWARN and VMDISABLE are not valid together");
#endif
#ifdef LCF_NOKEYBOARD
    if (cfg_get_flag(cf_all,"nokbdisable")) {
        descr->flags |= FLAG_NOKBDISABLE;
	param2.flag2 |= FLAG2_NOKBD;
    }
#endif

#if 1
    if (cfg_get_flag(cf_all,"mandatory") || cfg_get_flag(cf_options,
      "mandatory")) {
	if (!password) die("MANDATORY is only valid if PASSWORD is set.");
    }
    if (cfg_get_flag(cf_all,"restricted") || cfg_get_flag(cf_options,
      "restricted")) {
	if (!password) die("RESTRICTED is only valid if PASSWORD is set.");
	if ((descr->flags & FLAG_PASSWORD) && !cfg_get_flag(cf_all,"mandatory"))
	    descr->flags |= FLAG_RESTR;
    }
    if (password && *password && config_read) {
	warn("%s should be readable only "
	  "for root if using PASSWORD", config_file);
	config_read = 0;	/* suppress further warnings */
    }
#else
    if (cfg_get_flag(cf_all,"restricted") || cfg_get_flag(cf_options,
      "restricted")) {
	if (!password) die("RESTRICTED is only valid if PASSWORD is set.");
	descr->flags |= FLAG_RESTR;
    }
#endif
    if (cfg_get_flag(cf_all,"bmp-retain") ||
      cfg_get_flag(cf_options,"bmp-retain")) descr->flags |= FLAG_RETAIN;

    if (cfg_get_flag(cf_all,"single-key") ||
      cfg_get_flag(cf_options,"single-key")) descr->flags |= FLAG_SINGLE;

    fback = cfg_get_strg(cf_kernel,"fallback");
    if (fback) {
#ifdef LCF_READONLY
	die("This LILO is compiled READONLY and doesn't support the FALLBACK "
	  "option");
#else
	if (descr->flags & FLAG_LOCK)
	    die("LOCK and FALLBACK are mutually exclusive");
	else descr->flags |= FLAG_FALLBACK;
	*(unsigned short *) fallback_buf = DC_MAGIC;
	strcpy(fallback_buf+2,fback);
	fallback[fallbacks++] = stralloc(fback);
#endif
    }
#if 0
#if 1
    *(unsigned int *) descr->rd_size = 0; /* no RAM disk */
#else
    descr->rd_size = 0; /* no RAM disk */
#endif
    descr->start_page = 0; /* load low */
#endif
    map_begin_section();
    map_add_sector(fallback_buf);
    map_add_sector(options);
}


static void bsect_done(char *name,IMAGE_DESCR *descr)
{
    char *alias;
    int this_image,this;

    if (!*name) die("Invalid image name.");
    alias = cfg_get_strg(cf_all,"alias");
    this = alias ? get_image(NULL,alias,descr) : -1;
    this_image = get_image(name,cfg_get_strg(cf_all,"label"),descr);
    if ((descr->flags & FLAG_SINGLE) &&
      strlen(descrs.d.descr[this_image].name) > 1 &&
      (!alias || strlen(alias) > 1))
	die("SINGLE-KEYSTROKE requires the label or the alias to be only "
	  "a single character");
    if (verbose >= 0) {
	printf("Added %s",descrs.d.descr[this_image].name);
	if (alias) printf(" (alias %s)",alias);
#ifdef LCF_VIRTUAL
	if (descrs.d.descr[this_image].flags & FLAG_VMDEFAULT ||
		(this>=0 && (descrs.d.descr[this].flags & FLAG_VMDEFAULT)) )
	    printf(" @");
#endif
#ifdef LCF_NOKEYBOARD
	if (descrs.d.descr[this_image].flags & FLAG_NOKBDEFAULT ||
		(this>=0 && (descrs.d.descr[this].flags & FLAG_NOKBDEFAULT)) )
	    printf(" &");
#endif
	if (descrs.d.descr[this_image].flags & FLAG_TOOBIG ||
		(this>=0 && (descrs.d.descr[this].flags & FLAG_TOOBIG)) )
	    printf(" ?");
	if (this_image && this) putchar('\n');
	else printf(" *\n");
    }
    if (verbose >= 3) {
	printf("%4s<dev=0x%02x,hd=%d,cyl=%d,sct=%d>\n","",
	  descr->start.device,
	  descr->start.head,
	  descr->start.track,
	  descr->start.sector);
	if (*options) printf("%4s\"%s\"\n","",options);
    }
    if (verbose >= 1) putchar('\n');   /* makes for nicer spacing */
}


int bsect_number(void)
{
 /* -1 means default= did not exist */
    return image_base ? -1 : image;
}


static void unbootable(void)
{
#if 0
    fflush(stdout);
    fprintf(errstd,"\nCAUTION: The system is unbootable !\n");
    fprintf(errstd,"%9sRun LILO again to correct this.","");
#else
    warn("The system is unbootable !\n"
          "\t Run LILO again to correct this.");
#endif    
}


#ifdef LCF_VIRTUAL
void check_vmdefault(void)
{
    char * deflt;
    int i;
    
    if ( (deflt = cfg_get_strg(cf_options,"vmdefault")) ) {
	for (i=0; i<image; ++i) {
	    if (descrs.d.descr[i].flags & FLAG_VMDEFAULT) {
	        if (descrs.d.descr[i].flags & FLAG_VMDISABLE)
		    die("VMDEFAULT image cannot have VMDISABLE flag set");

                return;
	    }
	}
	die("VMDEFAULT image does not exist.");
    }
}
#endif

#ifdef LCF_NOKEYBOARD
void check_nokbdefault(void)
{
    char * deflt;
    int i;
    
    if ( (deflt = cfg_get_strg(cf_options,"nokbdefault")) ) {
	for (i=0; i<image; ++i) {
	    if (descrs.d.descr[i].flags & FLAG_NOKBDEFAULT) {
		if (descrs.d.descr[i].flags & FLAG_NOKBDISABLE)
		    die("NOKBDEFAULT image cannot have NOKBDISABLE flag set");

		return;
	    }
	}
	die("NOKBDEFAULT image does not exist.");
    }
}
#endif


void check_fallback(void)
{
    char *start,*end;
    int i,image;

    for (i = 0; i < fallbacks; i++) {
	for (start = fallback[i]; *start && *start == ' '; start++);
	if (*start) {
	    for (end = start; *end && *end != ' '; end++);
	    if (*end) *end = 0;
	    for (image = 0; image < MAX_IMAGES; image++)
#ifdef LCF_IGNORECASE
		if (!strcasecmp(descrs.d.descr[image].name,start)) break;
#else
		if (!strcmp(descrs.d.descr[image].name,start)) break;
#endif
	    if (image == MAX_IMAGES) die("No image \"%s\" is defined",start);
	}
    }
}

void check_unattended(void)
{
    if ( (descrs.d.descr[0].flags & (FLAG_PASSWORD + FLAG_RESTR) )
							== FLAG_PASSWORD
		&&  cfg_get_flag(cf_options,"unattended") )
	die("Mandatory PASSWORD on default=\"%s\" defeats UNATTENDED",
		descrs.d.descr[0].name);
}


void bsect_update(char *backup_file, int force_backup, int pass)
{
    BOOT_SECTOR bsect_wr;
    int temp;
static int timestamp = 0;

    if (pass>=0) {
	temp = make_backup(backup_file, force_backup, &bsect_orig,
    						boot_dev_nr, "boot sector");
	if (temp && !timestamp) bsect.par_1.timestamp = timestamp = temp;
    }

#ifndef LCF_UNIFY
# error "Bios Translation algorithms require '-DUNIFY' in Makefile"
#endif
    if (pass<1) {	/* BIOS_TT logic */
	MENUTABLE *menu = &menuparams;
	map_descrs(&descrs, menu->mt_descr, &menuparams.dflcmd);
	menuparams.raid_dev_mask = raid_mask((int*)menuparams.raid_offset);
	memcpy(menuparams.serial_no, serial_no, sizeof(serial_no));
	memcpy(table+256, &menuparams, sizeof(menuparams));
	((int*)table)[SECTOR_SIZE/sizeof(int)-2] = crc32(table, SECTOR_SIZE-2*sizeof(int), CRC_POLY1);
	map_begin_section();
	map_add_sector(table);
#ifdef LCF_FIRST6
	/* still use 5 byte address */
	(void) map_write(&param2.keytab,1,0,0);
#else
	(void) map_write(&param2.keytab,1,0);
#endif
	map_close(&param2, here2);
    }	/* if (pass<1) ...	*/

if (pass>=0) {
    if (lseek(fd,0,SEEK_SET) < 0)
	die("lseek %s: %s",
		boot_devnam ? boot_devnam : dev.name,
		strerror(errno));

#if 1
    if (ireloc &&
    	  bsect.par_1.cli == 0xFA
    	 						 ) {
/* perform the relocation of the boot sector */
	int len = bsect.par_1.code_length;
	int space = BOOT_SIG_OFFSET - len;
	
	if (len==0) die ("First stage loader is not relocatable.");
	
	space &= 0xFFF0;	/* roll back to paragraph boundary */
	bsect_wr = bsect_orig;
	memcpy(&bsect_wr.sector[space], &bsect, len);
	if (space <= 0x80) {
	    bsect_wr.sector[0] = 0xEB;		/* jmp short */
	    bsect_wr.sector[1] = space - 2;
	    bsect_wr.sector[2] = 0x90;		/* nop */
	} else {
	    bsect_wr.sector[0] = 0xE9;		/* jmp near */
	    *(short*)&bsect_wr.sector[1] = space - 3;
	}
	if (bsect_wr.sector[space+1] == 0xEB)	{  /* jmp short */
	    len = space>>4;
	    space += (signed)bsect_wr.sector[space+2] + 3;
	    if (bsect_wr.sector[space] == 0xB8)	/* mov ax,#07C0 */
		*(short*)&bsect_wr.sector[space+1] += len;
	}
/***	bsect = bsect_orig;  ***/
	if (verbose >= 1) printf("Boot sector relocation performed\n");
    }
    else bsect_wr = bsect;
#endif    	

 /* failsafe check */
#if 1
    if (verbose >= 3) {
	printf("Failsafe check:  boot_dev_nr = 0x%04x 0x%04x\n", boot_dev_nr, has_partitions(boot_dev_nr));
	/*** if (do_md_install) ***/ {
	    printf("map==boot = %d    map s/n = %08X\n",
		!!(bsect_wr.par_1.prompt & FLAG_MAP_ON_BOOT),
		bsect_wr.par_1.map_serial_no
	    );
	}
    }
#endif
    if (
      has_partitions(boot_dev_nr) &&
      (P_MASK(boot_dev_nr)&boot_dev_nr)==0 &&
      memcmp(bsect.sector+MAX_BOOT_SIZE, bsect_wr.sector+MAX_BOOT_SIZE, 64+8)
      )
    	die("LILO internal error:  Would overwrite Partition Table");
 /* failsafe check */
    	
    sync();		/* this may solve possible kernel buffer problem */
	
    if (!test && write(fd, (char *)&bsect_wr, SECTOR_SIZE) != SECTOR_SIZE)
	die("write %s: %s",boot_devnam ? boot_devnam : dev.name,
	  strerror(errno));

} /* if (pass>=0) ... */

    if (use_dev_close) dev_close(&dev);
    else if (close(fd) < 0) {
	    unbootable();
	    die("close %s: %s",boot_devnam,strerror(errno));
	}

#if 0
    if (pass==0) {
#else
    if (pass<1) {
#endif
	pw_file_update(passw);
	temp_unregister(temp_map);
	if (rename(temp_map,map_name) < 0) {
	    unbootable();
	    die("rename %s %s: %s",temp_map,map_name,strerror(errno));
	}
    }
/*  (void) sync();   Now handled in lilo.c (atexit(sync)) */
	if (verbose>=6) printf("End  bsect_update\n");
	fflush(stdout);
}


void bsect_cancel(void)
{
#if 0
    map_descrs(&descrs, bsect.par_1.descr, &bsect.par_1.dflcmd);
#endif
    map_close(NULL,0);
    if (!use_dev_close) (void) close(fd);
    else dev_close(&dev);
    temp_unregister(temp_map);
    if (verbose<9) (void) remove(temp_map);
}


static int present(char *var)
{
    char *path;

    if (!(path = cfg_get_strg(cf_top,var))) die("No variable \"%s\"",var);
    if (!access(path,F_OK)) return 1;
    if (!cfg_get_flag(cf_all,"optional") && !cfg_get_flag(cf_options,
      "optional")) return 1;
    if (verbose >= 0) printf("Skipping %s\n",path);
    return 0;
}


static int initrd_present(void)
{
    char *path;

    path = cfg_get_strg(cf_kernel, "initrd");
    if (!path) path = cfg_get_strg(cf_options, "initrd");
    if (!path) return 1;
    if (!access(path,F_OK)) return 1;
    if (!cfg_get_flag(cf_all,"optional") && !cfg_get_flag(cf_options,
      "optional")) return 1;
    if (verbose >= 0) printf("Skipping %s\n", cfg_get_strg(cf_top, "image"));
    return 0;
}


void do_image(void)
{
    IMAGE_DESCR descr;
    char *name;

/*    memset(&descr, 0, sizeof(descr));  	Done in "bsect_common" */
    cfg_init(cf_image);
    (void) cfg_parse(cf_image);
    if (present("image") && initrd_present()) {
	bsect_common(&descr, 1);
	descr.flags |= FLAG_KERNEL;
	name = cfg_get_strg(cf_top,"image");
	if (!cfg_get_strg(cf_image,"range")) boot_image(name,&descr);
	else boot_device(name,cfg_get_strg(cf_image,"range"),&descr);
	bsect_done(name,&descr);
    }
    cfg_init(cf_top);
}


void do_other(void)
{
    IMAGE_DESCR descr;
    char *name, *loader;

/*    memset(&descr, 0, sizeof(descr));  	Done in "bsect_common" */
    cfg_init(cf_other);
    cfg_init(cf_kernel); /* clear kernel parameters */
    curr_drv_map = curr_prt_map = 0;
    (void) cfg_parse(cf_other);
    if (present("other")) {
	bsect_common(&descr, 0);
	name = cfg_get_strg(cf_top,"other");
	loader = cfg_get_strg(cf_other,"loader");
	if (!loader) loader = cfg_get_strg(cf_options,"loader");
	boot_other(loader,name,cfg_get_strg(cf_other,"table"),&descr);
	bsect_done(name,&descr);
    }
    cfg_init(cf_top);
}


void bsect_uninstall(char *boot_dev,char *backup_file,int validate)
{
    struct stat st;
    char temp_name[PATH_MAX+1];
    int bck_file;

    open_bsect(boot_dev);
    if (bsect.sector[BOOT_SIG_OFFSET] != BOOT_SIGNATURE0 || bsect.sector[BOOT_SIG_OFFSET+1] != BOOT_SIGNATURE1)
	die("Boot sector of %s does not have a boot signature",boot_dev ?
	  boot_dev : dev.name);
    if (!strncmp(bsect.par_1.signature-4,"LILO",4))
	die("Boot sector of %s has a pre-21 LILO signature",boot_dev ?
	  boot_dev : dev.name);
    if (strncmp(bsect.par_1.signature,"LILO",4))
	die("Boot sector of %s doesn't have a LILO signature",boot_dev ?
	  boot_dev : dev.name);
    if (!backup_file) {
	sprintf(temp_name,BACKUP_DIR "/boot.%04X",boot_dev_nr);
	backup_file = temp_name;
    }
    if ((bck_file = open(backup_file,O_RDONLY)) < 0)
	die("open %s: %s",backup_file,strerror(errno));
    if (fstat(bck_file,&st) < 0)
	die("fstat %s: %s",backup_file,strerror(errno));
    if (validate && st.st_mtime != bsect.par_1.timestamp)
	die("Timestamp in boot sector of %s differs from date of %s\n"
	  "Try using the -U option if you know what you're doing.",boot_dev ?
	  boot_dev : dev.name,backup_file);
    if (verbose > 0) printf("Reading old boot sector.\n");
    if (read(bck_file,(char *) &bsect,PART_TABLE_OFFSET) != PART_TABLE_OFFSET)
	die("read %s: %s",backup_file,strerror(errno));
    if (lseek(fd,0,SEEK_SET) < 0)
	die("lseek %s: %s",boot_dev ? boot_dev : dev.name,strerror(errno));
    if (verbose > 0) printf("Restoring old boot sector.\n");
    if (write(fd,(char *) &bsect,PART_TABLE_OFFSET) != PART_TABLE_OFFSET)
	die("write %s: %s",boot_dev ? boot_dev : dev.name,strerror(errno));
    if (use_dev_close) dev_close(&dev);
    else if (close(fd) < 0) {
	    unbootable();
	    die("close %s: %s",boot_devnam,strerror(errno));
	}
    exit(0);
}


void bsect_raid_update(char *boot_dev, unsigned int raid_offset, 
	char *backup_file, int force_backup, int pass, int mask)
{
    BOOT_SECTOR bsect_save;
    int bios;
    int prompt = bsect.par_1.prompt;

    if (pass<0) bsect_update(backup_file, force_backup, pass);

    if (pass != 0) {    
	bsect_save = bsect;			/* save the generated boot sector */
	open_bsect(boot_dev);
	memcpy(&bsect, &bsect_save, MAX_BOOT_SIZE);	/* update the subject boot sector */
	bsect.par_1.raid_offset = raid_offset;	/* put in the new partition offset */
	bsect.par_1.prompt &= mask;		/* clear all RAID flags */
	bsect.par_1.prompt |= raid_flags;	/* update the raid flags */

	bios = (raid_flags&FLAG_RAID_DEFEAT) ? bios_map : bios_boot;
	if (!cfg_get_flag(cf_options, "static-bios-codes")) {
	    if (verbose>=2) printf("Using s/n from device 0x%02X\n", bios);
	    bsect.par_1.map_serial_no = serial_no[bios - 0x80];
	}

#ifdef LCF_FIRST6
/* lines added 22.5.7 */
	((SECTOR_ADDR6*)&bsect.par_1.secondary)->device = bios;
#else
/* lines added 22.5.6 */
	bsect.par_1.secondary.device &= ~DEV_MASK;
	bsect.par_1.secondary.device |= bios;
#endif
/* ************************************ */

	bsect.sector[BOOT_SIG_OFFSET] = BOOT_SIGNATURE0;
	bsect.sector[BOOT_SIG_OFFSET+1] = BOOT_SIGNATURE1;
    }
    
    if (pass<0) pass = -pass;
    
    bsect_update(backup_file, force_backup, pass);

    bsect.par_1.prompt = prompt;	/* restore the flag byte */
}


