/* netflash.c:
 *
 * Copyright (C) 2000,  Lineo (www.lineo.com)
 * Copyright (C) 1999-2000,  Greg Ungerer (gerg@snapgear.com)
 *
 * Copied and hacked from rootloader.c which was:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <sys/mount.h>
#include <string.h>
#ifndef VERSIONTEST
#include <linux/autoconf.h>
#include <config/autoconf.h>
#endif
#include <ctype.h>
#include "fileblock.h"
#include "versioning.h"

#ifndef VENDOR
#define VENDOR "Vendor"
#endif
#ifndef PRODUCT
#define PRODUCT "Product"
#endif
#ifndef VERSION
#define VERSION "1.0.0"
#endif

/****************************************************************************/

char imageVendorName[MAX_VENDOR_SIZE];
char imageProductName[MAX_PRODUCT_SIZE];
char imageVersion[MAX_VERSION_SIZE];

/****************************************************************************/

extern struct blkmem_program_t * prog;

static const char our_vendor_name[] = VENDOR;
static const char our_product_name[] = PRODUCT;
static char our_image_version[] = VERSION;

/****************************************************************************/

static int get_string(char *str, int len);
static int check_version_info(char *version, char *new_version);
static int get_version_bits(char *version, char *ver_long, char *letter,
		int *num, char *lang);
static int minor_to_int(char letter, int num);

/**
 * name is a simple product or vendor name.
 * namelist is either a comma separated list of names (may just be one)
 * 
 * Returns true if the name exists in the list or false if not.
 *
 * e.g. check_match("SG550", "SG530,SME530,SG550,SME550") returns true
 *  */
static int check_match(const char *name, const char *namelist)
{
	char *checklist = strdup(namelist);
	int ret = 0;

	const char *token = strtok(checklist, ",");
	while (token) {
		if (strcmp(name, token) == 0) {
			ret = 1;
			break;
		}
		token = strtok(0, ",");
	}
	free(checklist);
	return ret;
}

/****************************************************************************/

/*
 * Code to check that we are putting the correct type of flash into this
 * unit.
 * This code also removes the versioning information from the end
 * of the memory buffer.
 *
 * ret:
 *		0 - everything is correct.
 *		1 - the product name is incorrect.
 *		2 - the vendor name is incorrect.
 *		3 - the version is the same.
 *		4 - the version is older.
 *		5 - the version is invalid.
 *		6 - the version language is different.
 */

/*
 * The last few bytes of the image look like the following:
 *
 *  \0version\0vendore_name\0product_namechksum
 *	the chksum is 16bits wide, and the version is no more than 20bytes.
 *
 * version is w.x.y[nz], where n is ubpi, and w, x, y and z are 1 or 2 digit
 * numbers.
 *
 * vendorName and productName may be a comma separated list of names
 * which are acceptable
 */
int check_vendor(int endOffset, int *versionLength)
{
	int versionInfo;

	/*
	 * Point to what should be the last byte in the product name string.
	 */
	if (fb_seek_end(endOffset + 1) != 0)
		return 5;

	*versionLength = 0;
	/*
	 * Now try to get the vendor/product/version strings, from the end of the
	 * image, and figure out the length of the strings to return as well
	 */
	if (get_string(imageProductName, MAX_PRODUCT_SIZE) != 0)
		return 5;
	*versionLength += strlen(imageProductName) + 1;

	if (get_string(imageVendorName, MAX_VENDOR_SIZE) != 0)
		return 5;
	*versionLength += strlen(imageVendorName) + 1;

	if (get_string(imageVersion, MAX_VERSION_SIZE) != 0)
		return 5;
	*versionLength += strlen(imageVersion) + 1;

	/*
	 * Check the product name. Our product name may be a comma separated list of names.
	 */
	if (!check_match(imageProductName, our_product_name)) {
		return 1;
	}

	/*
	 * Check the vendor name. Our vendor name may be a comma separated list of names.
	 */
	if (!check_match(imageVendorName, our_vendor_name)) {
		return 2;
	}

	/*
	 * Check the version number.
	 */
	versionInfo = check_version_info(our_image_version, imageVersion);

	return versionInfo;
}


/* get_string
 *
 * This gets a printable string from the memory buffer.
 * It searchs backwards for a non-printable character or a NULL terminator.
 *
 * inputs:
 *
 * str/len - the buffer to store the string in.
 *
 * ret:
 *
 * -1 - we couldn't find the string.
 * 0 - success
 */
int get_string(char *str, int len)
{
	int i, j;
	char c;

	for (i = 0; i < len; i++) {
		fb_peek(str + i, 1);
		if (fb_seek_dec(1) != 0)
			return -1;
		if (!str[i])
			break;
		if (!isprint(str[i]))
			return -1;
	}
	if (i == 0 || i >= len)
		return -1;

	/* We read string in reverse order, so reverse it again */
	for (j=0; j<i/2; j++) {
		c = str[j];
		str[j] = str[i-j-1];
		str[i-j-1] = c;
	}

	return 0;
}


#define NUM_VERSION_ELEMS 9
/* check_version_info
 *
 * Check with the version number in imageVersion is a valid
 * upgrade to the current version.
 * The version is ALWAYS of the form major.minor.minor or it is invalid.
 * We determine whether something is older (less than) or newer,
 * by simply using a strcmp.  This functionality will change over
 * time to reflect intuitive notions of what constitutes reasonable versioing.
 *
 * inputs:
 *
 * curr_version - the version of the current flash image.
 * recv_version - the version of the new flash image we just received.
 *
 * ret:
 * 		0 - it all worked perfectly and the version looks okay.
 *		3 - the new version is the same.
 *		4 - the new version is older.
 *		5 - the new version is invalid.
 *		6 - the version language is different.
 */
int check_version_info(char *curr_version, char *recv_version)
{
	char new_ver[NUM_VERSION_ELEMS];
	char old_ver[NUM_VERSION_ELEMS];
	char old_version[MAX_VERSION_SIZE];
	char new_version[MAX_VERSION_SIZE];
	char new_lang[MAX_LANG_SIZE];
	char old_lang[MAX_LANG_SIZE];
	char new_letter, old_letter;
	int new_minor, old_minor;
	int res;
	int old, new;
	
	strncpy(old_version, curr_version, sizeof(old_version));
	old_version[sizeof(old_version)-1] = '\0';
	strncpy(new_version, recv_version, sizeof(new_version));
	new_version[sizeof(new_version)-1] = '\0';
	
	if(!get_version_bits(new_version, new_ver, &new_letter, &new_minor,
			new_lang))
		return 5;

	if(!get_version_bits(old_version, old_ver, &old_letter, &old_minor,
			old_lang))
		return 5;
	
	if (strcmp(old_lang, new_lang) != 0)
		return 6;
	res = strcmp(old_ver, new_ver);
	if(res < 0)
		return 0;
	else if(res > 0)
		return 4;
	else{			/*we have to look at the minor numbers and the char*/
		if((new = minor_to_int(new_letter, new_minor)) > \
			(old = minor_to_int(old_letter, old_minor)))
			return 0;
		else if(new == old)
			return 3;
		else
			return 4;
	}
} 
#undef NUM_VERSION_ELEMS
#undef MAX_VERSION_SIZE



static int get_version_bits(char *version, char *ver_long, char *letter,
		int *num, char *lang)
{
	int i;
	char *tmp;
	int len;
	char *eptr;
	char ver_tmp[10] = {'\0'};
	ver_long[0] = '\0';

	/* Extrat the language suffix */
	eptr = strchr(version, '\0');
	while (--eptr > version && isupper(*eptr));
	if (eptr == version)
		return 0;
	eptr++;
	for (i=0; (lang[i] = eptr[i]) != '\0'; i++);
	*eptr-- = '\0';

	/* Versions ending in jj are Johnson & Johnson custom images
	 * ignore the jj - it's for their version tracking only
	 */
	if (eptr >= version+2 && *eptr == 'j' && *(eptr - 1) == 'j') {
		*eptr-- = '\0'; *eptr-- = '\0';
	}

	/* Versions with unnumbered trailing letters will be treated as [u|b|p|i]0 */
	if (strchr("bupi", *eptr) != NULL) {
		eptr[1] = '0';
		eptr[2] = '\0';
	}

	tmp = strtok(version, ".");

	while(tmp != NULL){
		if((len = strlen(tmp)) == 1){
			if(!isdigit(tmp[0]))
				return 0;
			strncat(ver_tmp, "0", sizeof(ver_tmp) - strlen(ver_tmp));
		}else if(len == 2){
			if((!(isdigit(tmp[0]))) && (!(isdigit(tmp[1]))))
				return 0;
		}else if(len == 3){
			if((!(isdigit(tmp[0]))) || ((isdigit(tmp[1]))))
				return 0;
			strncat(ver_tmp, "0", sizeof(ver_tmp) - strlen(ver_tmp));
		}else if(len == 4){
			if(!((((isdigit(tmp[0]))) && (!(isdigit(tmp[1]))) && 
				((isdigit(tmp[2]))) && ((isdigit(tmp[3])))) ||
			  (((isdigit(tmp[0]))) && ((isdigit(tmp[1]))) && 
				(!(isdigit(tmp[2]))) && ((isdigit(tmp[3]))))))
				return 0;
			if(((isdigit(tmp[0]))) && (!(isdigit(tmp[1]))) && 
				((isdigit(tmp[2]))) && ((isdigit(tmp[3]))))
				strncat(ver_tmp, "0", sizeof(ver_tmp) - strlen(ver_tmp));
		}
		strncat(ver_tmp, tmp, sizeof(ver_tmp) - strlen(ver_tmp));
		tmp = strtok(NULL, ".");
	}
	
	if(((len = strlen(ver_tmp)) == 7) || (len > 9))
		return 0;
	if(strlen(ver_tmp) > 6){
		tmp = &(ver_tmp[6]);

		/*
		 * We only support an (u)pdate > (b)eta > (p)re-release
		 * '>' denotes more recent (greater version number) to the left.
		 */
		if((*tmp != 'p') && (*tmp != 'b') && (*tmp != 'u'))
			return 0;

		*letter = *tmp;
		*tmp = '\0';
		tmp++;

		if(*tmp == '\0')	/*if we have a letter, we MUST have a number*/
			return 0;
		*num = strtol(tmp, &eptr, 10);

		if((*eptr) != '\0') /*we should have used up the entier string*/
			return 0;		
		strcpy(ver_long, ver_tmp);
		return 1;
	}else if(len == 6){
		*letter = '\0';
		*num = 0;
		strcpy(ver_long, ver_tmp);
		return 1;
	}else
		return 0;
}


int minor_to_int(char letter, int num)
{
	int res=0;
	if(letter == 'u')
		res+=300;
	if(letter == '\0'){
		res+=200;
		return res;
	}
	if(letter == 'b')
		res+=100;

	/* Otherwise it is 'p' or something unknown.
         * Just leave it as-is.
         */

	return res + num;
}

/****************************************************************************/

#ifdef VERSIONTEST
int main(int argc, char *argv[])
{
	char ver[9];
	char letter;
	int minor;
	char lang[10];
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: versiontest <version>\n");
		exit(1);
	}

	rc = get_version_bits(argv[1], ver, &letter, &minor, lang);
	printf("rc: %d\n", rc);
	if (rc) {
		printf("ver: %s\n", ver);
		printf("type: %c\n", letter);
		printf("minor: %d\n", minor);
		printf("lang: %s\n", lang);
	}
}
#endif

#ifdef CONFIG_PROP_LOGD_LOGD
void log_upgrade(void) {
	char *av[20];
	int ac = 0;
	pid_t pid;

	av[ac++] = "logd";
	av[ac++] = "firmware";
	av[ac++] = our_image_version;
	av[ac++] = imageVersion;
	av[ac++] = NULL;

	pid = vfork();
	if (pid == 0) {
		execv("/bin/logd", av);
		_exit(1);
	}
	if (pid != -1)
		while (waitpid(pid, NULL, 0) == -1 && errno == EINTR);
}
#endif
