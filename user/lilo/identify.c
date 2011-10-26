/* identify.c  -  Translate label names to kernel paths */

/* 
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "lilo.h"
#include "common.h"
#include "cfg.h"

char *identify;
static char *opt;
static char *first, *dflt;
static int idefault;


static void do_identify(char *var,char type)
{
    char *label,*path,*alias,*initrd,*keytab,*appstr,*dtem,*addappstr;
    char *rootstr;
    int root,image, ramdisk, kt, append;

#if 1
    image = !!strchr(opt,'i');
    ramdisk = !!strchr(opt,'r');
    kt = !!strchr(opt,'k');
    append = !!strchr(opt,'a');
    root = !!strchr(opt,'R');
    if (opt && !image && !ramdisk && !kt && !append
    	&& !idefault && !root) exit(1);
/*    if (!opt) image = 1; */
#else
    image = ramdisk = 1;
    printf("do_identify:  opt=\"%s\"\n", opt);
#endif
    
    label = strrchr(path = cfg_get_strg(cf_identify,var),'/');
    if (label) label++;
    if (cfg_get_strg(cf_all,"label")) label = cfg_get_strg(cf_all,"label");
    else if (!label) label = path;

    if (!first) first = stralloc(label);
    
    alias = cfg_get_strg(cf_all,"alias");
    dtem = cfg_get_strg(cf_options,"default");

    if (verbose>=2) printf("identify: dtem=%s  label=%s\n", dtem, label);
#ifdef LCF_IGNORECASE
    if (dtem && (!strcasecmp(label,dtem) || (alias && !strcasecmp(alias,dtem)))) {
#else
    if (dtem && (!strcmp(label,dtem) || (alias && !strcmp(alias,dtem)))) {
#endif
	if (verbose>=2) printf("setting  dflt\n");
	dflt = dtem;
    }

    initrd = cfg_get_strg(cf_kernel,"initrd");
    if (!initrd) initrd = cfg_get_strg(cf_options,"initrd");
    keytab = cfg_get_strg(cf_options,"keytable");
    if (!keytab) keytab="us.ktl";
    appstr = cfg_get_strg(cf_kernel,"append");
    if (!appstr) appstr = cfg_get_strg(cf_options,"append");
    addappstr = cfg_get_strg(cf_kernel,"addappend");
    rootstr = cfg_get_strg(cf_kernel,"root");
    if (!rootstr) rootstr = cfg_get_strg(cf_options,"root");

#ifdef LCF_IGNORECASE
    if (!strcasecmp(label,identify) || (alias && !strcasecmp(alias,identify))) {
#else
    if (!strcmp(label,identify) || (alias && !strcmp(alias,identify))) {
#endif
	if (image) printf("%s\n",path);
	if (ramdisk) printf("%s\n",initrd?initrd:"No initial ramdisk specified");
	if (kt) printf("%s\n",keytab);
	if (append) {
	    if (!appstr && !addappstr)
		printf("No append= was specified\n");
	    else if ((appstr && !addappstr) || (!appstr && addappstr))
		printf("%s\n", appstr?appstr:addappstr);
	    else printf("%s %s\n", appstr, addappstr);
	}
	if (root) printf("%s\n",rootstr?rootstr:"No root specified");
	if (idefault) printf("%s\n", dflt ? dflt : first);
	exit(0);
    }
}


void id_image(void)
{
    cfg_init(cf_image);
    (void) cfg_parse(cf_image);
    do_identify("image",'i');
    cfg_init(cf_identify);
}


void id_other(void)
{
    cfg_init(cf_other);
    cfg_init(cf_kernel);
    curr_drv_map = curr_prt_map = 0;
    (void) cfg_parse(cf_other);
    cfg_init(cf_identify);
}


void identify_image(char *label,char *options)
{
    identify = label;
    opt = options;
    if (verbose>=2) printf("identify_image: id='%s' opt='%s'\n", label, options);
    idefault = !!strchr(opt,'D');
    if (idefault) identify = "";
    cfg_init(cf_identify);
    if (cfg_parse(cf_identify)) cfg_error("Syntax error");
    if (idefault && first) {
	printf("%s\n", dflt ? dflt : first);
	exit(0);
    }
    die("No image found for \"%s\"",label);
}
