/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@jlab.org>
 *  Some changes Copyright (C) 1997 Jon Nelson <nels0988@tc.umn.edu>
 *  Some changes Copyright (C) 1998 Martin Hinner <martin@tdp.cz>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* boa: hash.c */

#include "boa.h"
#include "syslog.h"

/* 
 * There are two hash tables used, each with a key/value pair
 * stored in a hash_struct.  They are:
 * 
 * mime_hashtable:
 *     key = file extension
 *   value = mime type
 * 
 * passwd_hashtable: 
 *     key = username
 *   value = home directory
 * 
 */

struct _hash_struct_ {
	char *key;
	char *value;
	struct _hash_struct_ *next;
};

typedef struct _hash_struct_ hash_struct;

#ifdef USE_BROWSERMATCH

#define BM_NOCHARSET     1         /* Don't send 'charset=' in response */

struct _browsermatch_struct {
  char *browser;
  int browser_len;
  int type;
  struct _browsermatch_struct *next;
};

typedef struct _browsermatch_struct browsermatch_struct;

#endif


static hash_struct *mime_hashtable[MIME_HASHTABLE_SIZE];
static hash_struct *passwd_hashtable[PASSWD_HASHTABLE_SIZE];
static hash_struct *virtualhost_hashtable[VIRTUALHOST_HASHTABLE_SIZE];

#ifdef USE_BROWSERMATCH
static browsermatch_struct *browsermatch_hashtable[BROWSERMATCH_HASHTABLE_SIZE];
#endif

/* 
 * Name: add_mime_type
 * Description: Adds a key/value pair to the mime_hashtable
 */

void add_mime_type(char *extension, char *type)
{
	int hash;
	hash_struct *current;

	if (!extension)
		return;

	hash = get_mime_hash_value(extension);

	current = mime_hashtable[hash];

	if (!current) {
		mime_hashtable[hash] = (hash_struct *) malloc(sizeof(hash_struct));
		mime_hashtable[hash]->key = strdup(extension);
		mime_hashtable[hash]->value = strdup(type);
		mime_hashtable[hash]->next = NULL;
	} else {
		while (current) {
			if (!strcmp(current->key, extension))
				return;			/* don't add extension twice */
			if (current->next)
				current = current->next;
			else
				break;
		}

		current->next = (hash_struct *) malloc(sizeof(hash_struct));
		current = current->next;

		current->key = strdup(extension);
		current->value = strdup(type);
		current->next = NULL;
	}
}

/*
 * Name: get_mime_hash_value
 * 
 * Description: adds the ASCII values of the file extension letters
 * and mods by the hashtable size to get the hash value
 */

int get_mime_hash_value(char *extension)
{
	int hash = 0;
	int index = 0;
	char c;

	while ((c = extension[index++]))
		hash += (int) c;

	hash %= MIME_HASHTABLE_SIZE;

	return hash;
}

/*
 * Name: get_mime_type
 *
 * Description: Returns the mime type for a supplied filename.
 * Returns default type if not found.
 */

char *get_mime_type(char *filename)
{
	char *extension;
	hash_struct *current;

	int hash;

	extension = strrchr(filename, '.');

	if (!extension || *extension++ == '\0')
		return default_type;

	hash = get_mime_hash_value(extension);
	current = mime_hashtable[hash];

	while (current) {
		if (!strcmp(current->key, extension))	/* hit */
			return current->value;
		current = current->next;
	}

	return default_type;
}

/*
 * Name: get_home_dir
 * 
 * Description: Returns a point to the supplied user's home directory.  
 * Adds to the hashtable if it's not already present.
 * 
 */

char *get_home_dir(char *name)
{
	struct passwd *passwdbuf;

	hash_struct *current, *trailer;
	int hash;

	/* first check hash table -- if username is less than four characters,
	   just hash to zero (this should be very rare) */
	
	if (server_chroot)
		return NULL;

	hash = ((strlen(name) < 4) ? 0 :
	  ((name[0] + name[1] + name[2] + name[3]) % PASSWD_HASHTABLE_SIZE));

	current = passwd_hashtable[hash];

	if (!current) {				/* definite miss */
		passwdbuf = getpwnam(name);

		if (!passwdbuf)			/* does not exist */
			return NULL;

		passwd_hashtable[hash] =
			(hash_struct *) malloc(sizeof(hash_struct));

		passwd_hashtable[hash]->key = strdup(name);
		passwd_hashtable[hash]->value = strdup(passwdbuf->pw_dir);
		passwd_hashtable[hash]->next = NULL;
		return passwd_hashtable[hash]->value;
	}
	while (current) {
		if (!strcmp(current->key, name))	/* hit */
			return current->value;

		trailer = current;
		current = current->next;
	}

	/* not in hash table -- let's look it up */

	passwdbuf = getpwnam(name);

	if (!passwdbuf)				/* does not exist */
		return NULL;

	/* exists -- have to add to hashtable */

	trailer->next = (hash_struct *) malloc(sizeof(hash_struct));
	current = trailer->next;

	current->key = strdup(name);
	current->value = strdup(passwdbuf->pw_dir);
	current->next = NULL;

	return current->value;
}

void dump_mime(void)
{
	int i;
	hash_struct *temp;
	for (i = 0; i < MIME_HASHTABLE_SIZE; ++i) {		/* these limits OK? */
		if (mime_hashtable[i]) {
			temp = mime_hashtable[i];
			while (temp) {
				hash_struct *temp_next;

				temp_next = temp->next;
				free(temp->key);
				free(temp->value);
				free(temp);

				temp = temp_next;
			}
			mime_hashtable[i] = NULL;
		}
	}
}

void dump_passwd(void)
{
	int i;
	hash_struct *temp;
	for (i = 0; i < PASSWD_HASHTABLE_SIZE; ++i) {	/* these limits OK? */
		if (passwd_hashtable[i]) {
			temp = passwd_hashtable[i];
			while (temp) {
				hash_struct *temp_next;

				temp_next = temp->next;
				free(temp->key);
				free(temp->value);
				free(temp);

				temp = temp_next;
			}
			passwd_hashtable[i] = NULL;
		}
	}
}

#ifdef USE_BROWSERMATCH

void add_browsermatch(char *browser, char *action)
{
 int act = 0;
 int hash;
 browsermatch_struct *current, *bm;

 if (!strcasecmp(action,"No-Charset")) act=BM_NOCHARSET; else
 if (!strcasecmp(action,"NoCharset")) act=BM_NOCHARSET; else
   {
#if 0
     fprintf(stderr,"Invalid BrowserMatch action: %s\n", action);
#endif
     exit (1);
   }

  hash = get_browser_hash_value(browser);

  current = browsermatch_hashtable[hash];
  bm = (browsermatch_struct *)malloc(sizeof(browsermatch_struct));
  if (!bm)
   die(OUT_OF_MEMORY);

  bm->next = current;
  bm->browser = strdup(browser);
  if (!bm->browser)
   die(OUT_OF_MEMORY);
  bm->browser_len = strlen(browser);
  bm->type = act;

  browsermatch_hashtable[hash] = bm;
}

/*
 * Name: get_browser_hash_value
 *
 * Description: returns hash value for 'browser' 
 */
int get_browser_hash_value(char *browser)
{
  int hash;
 
  hash = browser[0] % BROWSERMATCH_HASHTABLE_SIZE;     /* simple, or not? */
  return hash;
}

void browser_match_request(request *req)
{
 int len;
 int hash;
 browsermatch_struct *bm;

 if (!req->user_agent)
   return;

 hash = get_browser_hash_value(req->user_agent);
 bm = browsermatch_hashtable[hash];
 len = strlen(req->user_agent);

 while (bm)
  {
   if (len >= bm->browser_len)
     if (!strncasecmp(req->user_agent,bm->browser,bm->browser_len))
      {
       switch(bm->type)
        {
         case BM_NOCHARSET: req->send_charset=0;
                            break;
        }
      }
   bm = bm->next;
  }
}

#endif


/*
 * Name: add_virtual_host
 * Description: Adds a virtual host to virtualhost_hashtable
 */

void add_virtual_host(char *name, char *docroot)
{
  int hash;
  hash_struct *current;

  if (!name)
    return;
	

  hash = get_mime_hash_value(name);

  current = virtualhost_hashtable[hash];

  if (!current) {
    virtualhost_hashtable[hash] = (hash_struct *) malloc(sizeof(hash_struct));
    virtualhost_hashtable[hash]->key = strdup(name);
    virtualhost_hashtable[hash]->value = strdup(docroot);
    virtualhost_hashtable[hash]->next = NULL;
  } else {
    while (current) {
      if (!strcmp(current->key, name))
        return;     /* don't add extension twice */
      if (current->next)
        current = current->next;
      else
        break;
    }

    current->next = (hash_struct *) malloc(sizeof(hash_struct));
    current = current->next;

    current->key = strdup(name);
    current->value = strdup(docroot);
    current->next = NULL;
  }
 virtualhost = 1;
}

/*
 * Name: chroot_virtual_hosts
 *
 * Description: Translates virtual hosts to be accessible from server_chroot.
 */

void chroot_virtual_hosts()
{
  hash_struct *current;
  int hash;
	
	DBG(printf("chroot_virtual_hosts();\n");)
		
	if (!server_chroot)
		return;

	for (hash=0;hash<VIRTUALHOST_HASHTABLE_SIZE;hash++)
	{
	  current = virtualhost_hashtable[hash];

	  while (current) {
	    if (!strncmp(current->value, server_chroot, strlen(server_chroot)))
			{
				strcpy(current->value,current->value + strlen(server_chroot));
			}else
			{
#ifdef BOA_TIME_LOG
				log_error_time();
				fprintf(stderr,"Warning: Virtual host %s (%s)"
					 " is unaccessible from %s\n",
						current->key,current->value,server_chroot);
#endif
				syslog(LOG_ERR, "virtual host unaccessible");
			}
	    current = current->next;
	  }
	}
}


/*
 * Name: get_virtual_host
 *
 * Description: Returns the docroot of a supplied hostname.
 */

char *get_virtual_host(char *name)
{
  hash_struct *current;

  int hash;

  hash = get_mime_hash_value(name);
  current = virtualhost_hashtable[hash];

  while (current) {
    if (!strcasecmp(current->key, name)) /* hit */
      return current->value;
    current = current->next;
  }

  return NULL;
}

