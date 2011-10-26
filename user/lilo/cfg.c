/* cfg.c  -  Configuration file parser */
/*
Copyright 1992-1997 Werner Almesberger.
Copyright 1999-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

#include "lilo.h"
#include "common.h"
#include "temp.h"
#include "cfg.h"

#define NEW_PARSE !__MSDOS__

#define MAX_VAR_NAME MAX_TOKEN

#if !__MSDOS__
extern void do_image(void);
extern void do_other(void);
extern void do_disk(void);
extern void do_partition(void);

extern void id_image(void);
extern void id_other(void);

extern void do_map_drive(void);
extern void do_cr(void);
extern void do_change(void);
extern void do_cr_type(void);
extern void do_cr_reset(void);
extern void do_cr_part(void);
extern void do_cr_auto(void);


CONFIG cf_top[] = {
  { cft_strg, "image",		do_image,	NULL,NULL },
  { cft_strg, "other",		do_other,	NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_identify[] = {
  { cft_strg, "image",		id_image,	NULL,NULL },
  { cft_strg, "other",		id_other,	NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};
#endif /* !__MSDOS__ */

CONFIG cf_options[] = {
#if !__MSDOS__
  { cft_strg, "append",		NULL,		NULL,NULL },
  { cft_strg, "backup",		NULL,		NULL,NULL },
  { cft_strg, "bios-passes-dl",	NULL,		NULL,NULL },
  { cft_strg, "bitmap",		NULL,		NULL,NULL },
  { cft_strg, "bmp-colors",	NULL,		NULL,NULL },
  { cft_flag, "bmp-retain",	NULL,		NULL,NULL },
  { cft_strg, "bmp-table",	NULL,		NULL,NULL },
  { cft_strg, "bmp-timer",	NULL,		NULL,NULL },
  { cft_strg, "boot",		NULL,		NULL,NULL },
  { cft_strg, "boot-as",	NULL,		NULL,NULL },
  { cft_flag, "change-rules",	do_cr,		NULL,NULL },
  { cft_flag, "compact",	NULL,		NULL,NULL },
  { cft_strg, "default",	NULL,		NULL,NULL },
  { cft_strg, "delay",		NULL,		NULL,NULL },
  { cft_strg, "disk",		do_disk,	NULL,NULL },
  { cft_strg, "disktab",	NULL,		NULL,NULL },
  { cft_flag, "el-torito-bootable-cd",	NULL,		NULL,NULL },
  { cft_strg, "fallback",	NULL,		NULL,NULL },
  { cft_flag, "fix-table",     	NULL,		NULL,NULL },
  { cft_strg, "force-backup",	NULL,		NULL,NULL },
  { cft_flag, "geometric",      NULL,           NULL,NULL }, 
  { cft_flag, "ignore-table",   NULL,		NULL,NULL },
  { cft_strg, "initrd",		NULL,		NULL,NULL },
  { cft_strg, "install",	NULL,		NULL,NULL },
  { cft_strg, "keytable",	NULL,		NULL,NULL },
  { cft_flag, "large-memory",	NULL,		NULL,NULL },
  { cft_flag, "lba32",          NULL,           NULL,NULL }, 
  { cft_flag, "linear",     	NULL,		NULL,NULL },
  { cft_strg, "loader",		NULL,		NULL,NULL },
  { cft_flag, "lock",		NULL,		NULL,NULL },
  { cft_flag, "mandatory",	NULL,		NULL,NULL },
#endif /* !__MSDOS__ */
  { cft_strg, "map",		NULL,		NULL,NULL },
#if !__MSDOS__
  { cft_flag, "master-boot",	NULL,		NULL,NULL },
  { cft_strg, "menu-scheme",	NULL,		NULL,NULL },
  { cft_strg, "menu-title",	NULL,		NULL,NULL },
  { cft_strg, "message",	NULL,		NULL,NULL },
  { cft_flag, "nodevcache",	NULL,		NULL,NULL },
#ifdef LCF_NOKEYBOARD
  { cft_strg, "nokbdefault",	NULL,		NULL,NULL },
#endif
  { cft_flag, "noraid",		NULL,		NULL,NULL },
  { cft_flag, "nowarn",		NULL,		NULL,NULL },
  { cft_flag, "optional",	NULL,		NULL,NULL },
  { cft_strg, "password",	NULL,		NULL,NULL },
  { cft_flag, "prompt",		NULL,		NULL,NULL },
  { cft_strg, RAID_EXTRA_BOOT,	NULL,		NULL,NULL },
  { cft_strg, "ramdisk",	NULL,		NULL,NULL },
  { cft_flag, "read-only",	NULL,		NULL,NULL },
  { cft_flag, "read-write",	NULL,		NULL,NULL },
  { cft_flag, "restricted",	NULL,		NULL,NULL },
  { cft_strg, "root",		NULL,		NULL,NULL },
  { cft_strg, "serial",		NULL,		NULL,NULL },
  { cft_flag, "single-key",	NULL,		NULL,NULL },
  { cft_flag, "static-bios-codes",	NULL,		NULL,NULL },
  { cft_flag, "suppress-boot-time-BIOS-data",	NULL,	NULL,NULL },
  { cft_strg, "timeout",	NULL,		NULL,NULL },
  { cft_flag, "unattended",	NULL,		NULL,NULL },
  { cft_strg, "verbose",	NULL,		NULL,NULL },
  { cft_strg, "vga",		NULL,		NULL,NULL },
#ifdef LCF_VIRTUAL
  { cft_strg, "vmdefault",	NULL,		NULL,NULL },
#endif
#endif /* !__MSDOS__ */
  { cft_end,  NULL,		NULL,		NULL,NULL }};

#if !__MSDOS__
CONFIG cf_all[] = {
  { cft_strg, "alias",		NULL,		NULL,NULL },
  { cft_flag, "bmp-retain",	NULL,		NULL,NULL },
  { cft_flag, "bypass",		NULL,		NULL,NULL },
  { cft_strg, "fallback",	NULL,		NULL,NULL },
  { cft_strg, "label",		NULL,		NULL,NULL },
  { cft_strg, "literal",	NULL,		NULL,NULL },
  { cft_flag, "lock",		NULL,		NULL,NULL },
  { cft_flag, "mandatory",	NULL,		NULL,NULL },
#ifdef LCF_NOKEYBOARD
  { cft_flag, "nokbdisable",	NULL,		NULL,NULL },
#endif
  { cft_flag, "optional",	NULL,		NULL,NULL },
  { cft_strg, "password",	NULL,		NULL,NULL },
  { cft_flag, "restricted",	NULL,		NULL,NULL },
  { cft_flag, "single-key",	NULL,		NULL,NULL },
#ifdef LCF_VIRTUAL
  { cft_flag, "vmdisable",	NULL,		NULL,NULL },
  { cft_flag, "vmwarn",		NULL,		NULL,NULL },
#endif
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_kernel[] = {
  { cft_strg, "addappend",	NULL,		NULL,NULL },
  { cft_strg, "append",		NULL,		NULL,NULL },
  { cft_strg, "initrd",		NULL,		NULL,NULL },
  { cft_strg, "ramdisk",	NULL,		NULL,NULL },
  { cft_flag, "read-only",	NULL,		NULL,NULL },
  { cft_flag, "read-write",	NULL,		NULL,NULL },
  { cft_strg, "root",		NULL,		NULL,NULL },
  { cft_strg, "vga",		NULL,		NULL,NULL },
  { cft_link, NULL,		&cf_all,	NULL,NULL }};

CONFIG cf_image[] = {
  { cft_strg, "range",		NULL,		NULL,NULL },
  { cft_link, NULL,		&cf_kernel,	NULL,NULL }};

CONFIG cf_other[] = {
  { cft_strg, "boot-as",	NULL,		NULL,NULL },
  { cft_flag, "change",		do_change,	NULL,NULL },
  { cft_strg, "loader",		NULL,		NULL,NULL },
  { cft_strg, "map-drive",	do_map_drive,	NULL,NULL },
  { cft_flag, "master-boot",	NULL,		NULL,NULL },
  { cft_strg, "table",		NULL,		NULL,NULL },
  { cft_flag, "unsafe",		NULL,		NULL,NULL },
  { cft_link, NULL,		&cf_all,	NULL,NULL }};

CONFIG cf_disk[] = {
  { cft_strg, "bios",		NULL,		NULL,NULL },
  { cft_strg, "cylinders",	NULL,		NULL,NULL },
  { cft_strg, "heads",		NULL,		NULL,NULL },
  { cft_flag, "inaccessible",	NULL,		NULL,NULL },
  { cft_strg, "max-partitions",	NULL,		NULL,NULL },
  { cft_strg, "sectors",	NULL,		NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_partitions[] = {
  { cft_strg, "partition",	do_partition,	NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_partition[] = {
  { cft_strg, "start",		NULL,		NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_map_drive[] = {
  { cft_strg, "to",		NULL,		NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_change_rules[] = {
  { cft_flag, "reset",		do_cr_reset,	NULL,NULL },
  { cft_strg, "type",		do_cr_type,	NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_change_rule[] = {
  { cft_strg, "hidden",		NULL,		NULL,NULL },
  { cft_strg, "normal",		NULL,		NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_change[] = {
  { cft_flag, "automatic",	do_cr_auto,	NULL,NULL },
  { cft_strg, "partition",	do_cr_part,	NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_change_dsc[] = {
  { cft_flag, "activate",	NULL,		NULL,NULL },
  { cft_flag, "deactivate",	NULL,		NULL,NULL },
  { cft_strg, "set",		NULL,		NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};

CONFIG cf_bitmap[] = {
  { cft_strg, "bitmap",		NULL,		NULL,NULL },
  { cft_strg, "bmp-colors",	NULL,		NULL,NULL },
  { cft_strg, "bmp-table",	NULL,		NULL,NULL },
  { cft_strg, "bmp-timer",	NULL,		NULL,NULL },
  { cft_end,  NULL,		NULL,		NULL,NULL }};
#endif /* !__MSDOS__ */

#if NEW_PARSE

static CONFIG *keywords[] = {cf_top, cf_identify, cf_options, cf_all,
	cf_kernel, cf_image, cf_other, cf_disk, cf_partitions, cf_partition,
	cf_map_drive, cf_change_rules, cf_change_rule, cf_change, 
	cf_change_dsc, cf_bitmap, NULL };

#endif
	
static FILE *file;
static char flag_set;
static char *last_token = NULL,*last_item = NULL,*last_value = NULL;
static int line_num;
static char *file_name = NULL;
static int back = 0; /* can go back by one char */


int cfg_open(char *name)
{
    line_num = 1;
    if (!strcmp(name,"-")) file = stdin;

#if __MSDOS__
    else if (!strcasecmp(name,"none")) return -1;
#endif /* __MSDOS__ */

    else if (!(file = fopen(file_name = name,"r"))) {
#if !__MSDOS__
		die("Cannot open: %s", name);
#else  /* __MSDOS__ */
		warn("No configuration file: %s\n", name);
		return -1;
#endif /* __MSDOS__ */
    }

    return fileno(file);
}


void cfg_error(char *msg,...)
{
    va_list ap;

    fflush(stdout);
    va_start(ap,msg);
    vfprintf(errstd,msg,ap);
    va_end(ap);
    if (!file_name) fputc('\n',errstd);
    else fprintf(errstd," at or above line %d in file '%s'\n",line_num,file_name);
    exit(1);
}


static int next_raw(void)
{
    int ch;

    if (!back) return getc(file);
    ch = back;
    back = 0;
    return ch;
}


static int next(void)
{
    static char *var;
    char buffer[MAX_VAR_NAME+1];
    int ch,braced;
    char *put;

    if (back) {
	ch = back;
	back = 0;
	return ch;
    }
    if (var && *var) return *var++;
    ch = getc(file);
    if (ch == '\r')		/* strip DOS <cr> */
        ch = getc(file);
    if (ch == '\\') {
	ch = getc(file);
	if (ch == '$') return ch;
	ungetc(ch,file);
	return '\\';
    }
    if (ch != '$') return ch;
    ch = getc(file);
    braced = ch == '{';
    put = buffer;
    if (!braced) *put++ = ch;
    while (1) {
	ch = getc(file);
#if 0
	if (!braced && ch < ' ') {
	    ungetc(ch,file);
	    break;
	}
#endif
	if (ch == EOF) cfg_error("EOF in variable name");
	if (ch < ' ') cfg_error("control character in variable name");
	if (braced && ch == '}') break;
	if (!braced && !isalpha(ch) && !isdigit(ch) && ch != '_') {
	    ungetc(ch,file);
	    break;
	}
	if (put-buffer == MAX_VAR_NAME) cfg_error("variable name too long");
	*put++ = ch;
    }
    *put = 0;
#if !__MSDOS__
    if (!(var = getenv(buffer))) cfg_error("unknown variable \"%s\"",buffer);
#endif /* !__MSDOS__ */
    return next();
}


static void again(int ch)
{
    if (back) die("internal error: again invoked twice");
    back = ch;
}


static char *cfg_get_token(void)
{
    char buf[MAX_TOKEN+1];
    char *here;
    int ch,escaped;

    if (last_token) {
	here = last_token;
	last_token = NULL;
	return here;
    }
    while (1) {
	while ((ch = next()), ch == ' ' || ch == '\t' || ch == '\n')
	    if (ch == '\n') line_num++;
	if (ch == EOF) return NULL;
	if (ch != '#') break;
	while ((ch = next_raw()), ch != '\n')
	    if (ch == EOF) return NULL;
	line_num++;
    }
    if (ch == '=') return stralloc("=");
    if (ch == '"') {
	here = buf;
	while (here-buf < MAX_TOKEN) {
	    if ((ch = next()) == EOF) cfg_error("EOF in quoted string");
	    if (ch == '"') {
		*here = 0;
		return stralloc(buf);
	    }
	    if (ch == '\\') {
		ch = next();
		if (ch != '"' && ch != '\\' && ch != '\n')
		    cfg_error("Bad use of \\ in quoted string");
		if (ch == '\n') {
		    while ((ch = next()), ch == ' ' || ch == '\t');
		    if (!ch) continue;
		    again(ch);
		    ch = ' ';
		}
	    }
	    if (ch == '\n' || ch == '\t')
		cfg_error("\\n and \\t are not allowed in quoted strings");
	    *here++ = ch;
	}
	cfg_error("Quoted string is too long");
	return 0; /* not reached */
    }
    here = buf;
    escaped = 0;
    while (here-buf < MAX_TOKEN) {
	if (escaped) {
	    if (ch == EOF) cfg_error("\\ precedes EOF");
	    if (ch == '\n') line_num++;
	    else *here++ = ch == '\t' ? ' ' : ch;
	    escaped = 0;
	}
	else {
	    if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '#' ||
	      ch == '=' || ch == EOF) {
		again(ch);
		*here = 0;
		return stralloc(buf);
	    }
#if !__MSDOS__
	    if (!(escaped = (ch == '\\')))
#endif /* !__MSDOS__ */
		*here++ = ch;
	}
	ch = next();
    }
    cfg_error("Token is too long");
    return 0; /* not reached */
}


static void cfg_return_token(char *token)
{
    last_token = token;
}


static int cfg_next(char **item,char **value)
{
    char *this;

    if (last_item) {
	*item = last_item;
	*value = last_value;
	last_item = NULL;
	return 1;
    }
    *value = NULL;
    if (!(*item = cfg_get_token())) return 0;
    if (!strcmp(*item,"=")) cfg_error("Syntax error");
    if (!(this = cfg_get_token())) return 1;
    if (strcmp(this,"=")) {
	cfg_return_token(this);
	return 1;
    }
    if (!(*value = cfg_get_token())) cfg_error("Value expected at EOF");
    if (!strcmp(*value,"=")) cfg_error("Syntax error after %s",*item);
    return 1;
}


static void cfg_return(char *item,char *value)
{
    last_item = item;
    last_value = value;
}


void cfg_init(CONFIG *table)
{
    while (table->type != cft_end) {
	switch (table->type) {
	    case cft_strg:
		if (table->data) free(table->data);
	    case cft_flag:
		table->data = NULL;
		break;
	    case cft_link:
		table = ((CONFIG *) table->action)-1;
		break;
	    default:
		die("Unknown syntax code %d",table->type);
	}
	table++;
    }
}


static int cfg_do_set(CONFIG *table,char *item,char *value,int copy,
    void *context)
{
    CONFIG *walk;

    for (walk = table; walk->type != cft_end; walk++) {
	if (walk->name && !strcasecmp(walk->name,item)) {
	    if (value && walk->type != cft_strg)
		cfg_error("'%s' doesn't have a value",walk->name);
	    if (!value && walk->type == cft_strg)
		cfg_error("Value expected for '%s'",walk->name);
	    if (walk->data) {
		if (walk->context == context)
		    cfg_error("Duplicate entry '%s'",walk->name);
		else {
		    warn("Ignoring entry '%s'",walk->name);
		    if (!copy) free(value);
		    return 1;
		}
	    }
	    if (walk->type == cft_flag) walk->data = &flag_set;
	    else if (walk->type == cft_strg)
		    walk->data = copy ? stralloc(value) : value; 
	    walk->context = context;
	    if (walk->action) ((void (*)(void)) walk->action)();
	    break;
	}
	if (walk->type == cft_link) walk = ((CONFIG *) walk->action)-1;
    }
    if (walk->type != cft_end) return 1;
    cfg_return(item,value);
    return 0;
}


void cfg_set(CONFIG *table,char *item,char *value,void *context)
{
    if (cfg_do_set(table,item,value,1,context) != 1)
	cfg_error("cfg_set: Can't set %s",item);
}


void cfg_unset(CONFIG *table,char *item)
{
    CONFIG *walk;

    for (walk = table; walk->type != cft_end; walk++)
	if (walk->name && !strcasecmp(walk->name,item)) {
	    if (!walk->data) die("internal error (cfg_unset %s, unset)",item);
	    if (walk->type == cft_strg) free(walk->data);
	    walk->data = NULL;
	    return;
	}
    die("internal error (cfg_unset %s, unknown",item);
}

#if NEW_PARSE

static int cfg_end (char *item)
{
    CONFIG **key;
    CONFIG *c;

key = keywords;
while ((c = *key++)) {
    while (c->name) {
        if (!strcasecmp(c->name, item)) return 1;
        c++;
    }
}
    return 0;
}
#endif


int cfg_parse(CONFIG *table)
{
    char *item,*value;

    while (1) {
	if (!cfg_next(&item,&value)) return 0;
if(verbose>=6) printf("cfg_parse:  item=\"%s\" value=\"%s\"\n", item, value);
	if (!cfg_do_set(table,item,value,0,table)) {
#if NEW_PARSE==0
		return 1;
#else
	    if (cfg_end(item)) return 1;
	    else cfg_error("Unrecognized token \"%s\"", item);
#endif
	}
	free(item);
    }
}


int cfg_get_flag(CONFIG *table,char *item)
{
    CONFIG *walk;

    for (walk = table; walk->type != cft_end; walk++) {
	if (walk->name && !strcasecmp(walk->name,item)) {
	    if (walk->type != cft_flag)
		die("cfg_get_flag: operating on non-flag %s",item);
	    return !!walk->data;
	}
	if (walk->type == cft_link) walk = ((CONFIG *) walk->action)-1;
    }
    die("cfg_get_flag: unknown item %s",item);
    return 0; /* not reached */
}


char *cfg_get_strg(CONFIG *table,char *item)
{
    CONFIG *walk;

    for (walk = table; walk->type != cft_end; walk++) {
	if (walk->name && !strcasecmp(walk->name,item)) {
	    if (walk->type != cft_strg)
		die("cfg_get_strg: operating on non-string %s",item);
	    return walk->data;
	}
	if (walk->type == cft_link) walk = ((CONFIG *) walk->action)-1;
    }
    die("cfg_get_strg: unknown item %s",item);
    return 0; /* not reached */
}


#if !__MSDOS__
/* open the password file, passw=1 forces a new file to be created */

static char *pw_file_name;
FILE *pw_file = NULL;

FILE *cfg_pw_open(void)
{
    char name[MAX_TOKEN+1];
    struct stat buf;
    time_t conf;
    int fd;
    
    strcpy(name, file_name);	/* copy name of config file '/etc/lilo.conf' */
    strcat(name, PW_FILE_SUFFIX);
    pw_file_name = stralloc(name);
#if 1
    if (stat(file_name, &buf)) die("Cannot stat '%s'", file_name);
    conf = buf.st_mtime;
    if (!stat(pw_file_name, &buf) && conf>buf.st_mtime && !passw) {
        warn("'%s' more recent than '%s'\n"
              "   Running 'lilo -p' is recommended.",
              file_name, pw_file_name);
    }
#endif    

    if (passw & !test) {
	if (unlink(pw_file_name) && errno != ENOENT) die("Could not delete '%s'", pw_file_name);
	if ((fd = creat(pw_file_name, 0600)) < 0) die("Could not create '%s'", pw_file_name);
	(void) close(fd);
	pw_file = fopen(pw_file_name, "w+");
    }
    else if (passw) return (pw_file=NULL);
    else {
        if (!(pw_file = fopen(pw_file_name, "r"))) {
            if (!test) {
                passw = 1;			/* force writing */
		if ((fd = creat(pw_file_name, 0600)) < 0) die("Could not create '%s'", pw_file_name);
		(void) close(fd);
                pw_file = fopen(pw_file_name, "w+");
            }
            else return (pw_file=NULL);
        }
    }
    if (!pw_file) die("Could not create '%s'", pw_file_name);
#if 1
    if (!stat(pw_file_name, &buf) && (buf.st_mode&0044) ) {
        warn("'%s' readable by other than 'root'", pw_file_name);
    }
#endif    
    return pw_file;
}


/* allow only the "bitmap" keywords */

void cfg_bitmap_only(void)
{
    keywords[0] = cf_bitmap;
    keywords[1] = NULL;
}

#if BETA_TEST
void cfg_alpha_check(void)
{
    CONFIG **kw = keywords;
    CONFIG *cfg;
    
    while ((cfg=*kw)) {
	while (cfg[1].name) {
	    if (strcmp(cfg[0].name, cfg[1].name) >= 0) {
		die("cfg_alpha_check:  failure at '%s', '%s'", cfg[0].name, cfg[1].name);
	    }
	cfg++;
	}
    kw++;
    }
}
#endif

#endif /* !__MSDOS__ */
