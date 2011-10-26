/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  National Language Support (c) 1998 Martin Hinner <martin@tdp.cz>
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
 * $Id: nls.c,v 1.2 2000-09-13 06:13:07 davidm Exp $
 */

#include <stdio.h>
#include <fcntl.h>
#include "boa.h"

/*
 FIXME:
 Which codepage?
	 1. url
	 2. Accept-charset header
	 3. CodepageByBrowser
*/

#ifdef DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

char *local_codepage;

#ifdef USE_NLS

struct _cp_struct_ {
	char *name;
	char table[0x100];
	struct _cp_struct_ *next;
};

struct _cp_brows_ {
	char *browsermatch;
	char *codepage;
	struct _cp_brows_ *next;
};

typedef struct _cp_struct_ cp_struct;
typedef struct _cp_brows_ cp_brows;

static cp_struct *cp_hashtable [CODEPAGE_HASHTABLE_SIZE];
static cp_brows *cp_browsers;

/*
 * Name: get_cp_hash_value
 *
 * Description: adds the ASCII values of the file codepage letters
 * and mods by the hashtable size to get the hash value
 */
int get_cp_hash_value(char *name)
{
        int hash = 0;
        int index = 0;
        char c;

        while ((c = name[index++]))
                hash += (int) c;

        hash %= CODEPAGE_HASHTABLE_SIZE;

        return hash;
}


/*
 * Name: nls_load_codepage
 *
 * Description: Loads codepage conversion table from file `filename'
 */
void nls_load_codepage(char *name,char *filename)
{
	cp_struct *new_cp,*old;
	int f;
	int hash;
	
  old = cp_hashtable [get_cp_hash_value(name)];
	while (old)
	{
		if (!strcmp(name,old->name))
			return;
		old = old->next;
	}
	
	f = open(filename,O_RDONLY);
	if (f==-1)
	{
#ifdef BOA_TIME_LOG
		log_error_time();
		fprintf(stderr,"File %s not found\n",filename);
#endif
		return ;
	}
	
	new_cp = (cp_struct *)malloc(sizeof(cp_struct));
	new_cp->name = strdup(name);
	if (read(f,new_cp->table,0x100)!=0x100)
	{
#ifdef BOA_TIME_LOG
		log_error_time();
		fprintf(stderr,"Invalid codepage conversion file %s!\n",filename);
#endif
		free(new_cp->name);
		free(new_cp);
		close(f);
		return ;
	}
	new_cp->next = cp_hashtable [get_cp_hash_value(name)];
	cp_hashtable [get_cp_hash_value(name)] = new_cp;
	close(f);
}
/*
 * Name: get_nls_table
 *
 * Description: Returns the codepage conversion table.
 */

unsigned char *nls_get_table(char *name)
{
  cp_struct *current;

  int hash;
	
	DBG(printf("nls_get_table\n");)

  hash = get_cp_hash_value(name);
  current = cp_hashtable[hash];

  while (current) {
    if (!strcmp(current->name, name)) /* hit */
      return current->table;
    current = current->next;
  }

  return NULL;
}

/*
 * Name: nls_get_cp_hash_value
 *
 * Description: adds the ASCII values of the file letters
 * and mods by the hashtable size to get the hash value
 */
inline int nls_get_cp_hash_value(char *file)
{
	unsigned int hash = 0;
	unsigned int index = 0;
	unsigned char c;
	
	hash = file[index++];
	while ((c = file[index++]) && c != '/')
		hash += (unsigned int) c;

 	return hash % ALIAS_HASHTABLE_SIZE;
}


/*
 * Name: nls_try_redirect
 *
 * Description: Redirects client to new location if referer has codepage
 *	in url (like www.company.cz/asc/about/). This doesn't like frames. Me too.
 *	Returns 0 when redirected, else 1.
 */
int nls_try_redirect(request * req)
{
	char *url;
	alias *current;
	int hash;
	char buffer[(2*MAX_HEADER_LENGTH) + 1];
				
	DBG(printf("nls_try_redirect\n");)

	if (!req->referer)
		return 1;
	
	if (strlen(req->referer)<7)
		return 1;
	if (memcmp(req->referer,"http://",7))
		return 1;
	
	url = req->referer + 7;
	while ( (*url!='/') && (*url) ) url++;        /* Skip hostname & port */
	if (!*url)
		return 1;
	
  /* Find codepage `alias' */
  hash = nls_get_cp_hash_value(url);
 
  current = cp_url_hashtable[hash];
  while (current) {
		if (!memcmp(url, current->fakename,
		          current->fake_len)) {
      if (current->fakename[current->fake_len - 1] != '/' &&
	        url[current->fake_len] != '/' &&
	        url[current->fake_len] != '\0') {
	        break;
		      }
			if (server_port!=80)
				sprintf(buffer,"http://%s:%u",req->host?req->host:server_name,
						server_port);
				else
					sprintf(buffer,"http://%s",req->host?req->host:server_name);
			strcat(buffer,current->fakename);
			strcat(buffer,"/");
			strcat(buffer,req->request_uri+1);
			send_redirect_perm(req,buffer);
			return 0;
		}
		current = current->next;
	}
	
	return 1;
}

/*
 * Name: nls_set_codepage
 *
 * Description: Set codepage for current request
 */
void nls_set_codepage(request * req)
{
	cp_brows *current;
	
	DBG(printf("nls_set_codepage\n");)
	if (strncmp(get_mime_type(req->request_uri),"text/",5))
	{
		req->cp_table = 0;
		req->send_charset = 0;
		return ;
	}
	
	if ( (req->user_agent) && (!req->cp_name) ) 
	{
		current = cp_browsers;
		while (current)
		{
			if (strmatch(req->user_agent,current->browsermatch))
			{
				req->cp_name = current->codepage;
				break;
			}
			current = current->next;
		}
	}	
	
	if (req->cp_name)
	{
		if (!strcmp(req->cp_name,"no-conv"))
		{
			req->cp_name = local_codepage;
			return;
		}
	
		if (!strcmp(req->cp_name,"no-charset"))
		{
			req->send_charset=0;
			req->cp_name = 0;
			return ;
		}
		req->cp_table = nls_get_table(req->cp_name);
	}
}

/*
 * Name: add_cp_brows()
 *
 * Description: Add codepage for matching browser to table.
 */
void add_cp_brows(char *browsermatch,char *codepage)
{
	cp_brows *new;
	
	new = (cp_brows*)malloc(sizeof(cp_brows));
	new->browsermatch = strdup(browsermatch);
	new->codepage = strdup(codepage);
	new->next = cp_browsers;
	cp_browsers = new;
}

void nls_convert(unsigned char * buffer, unsigned char * table, long count)
{
	int i;

	for (i=0;i<count;i++)
		buffer[i] = table [ buffer[i] ];
}

#endif
