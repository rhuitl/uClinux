/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@jlab.org>
 *  Some changes Copyright (C) 1996,97 Jon Nelson <nels0988@tc.umn.edu>
 *  Some changes Copyright (C) 1996 Russ Nelson <nelson@crynwr.com>
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

/* boa: alias.c */

#include "boa.h"
#include <sys/stat.h>
#include "syslog.h"

#ifdef EMBED
#undef index
#endif

alias *alias_hashtable[ALIAS_HASHTABLE_SIZE];
#ifdef USE_NLS
alias *cp_url_hashtable[ALIAS_HASHTABLE_SIZE];
#endif

inline int get_alias_hash_value(char *file);

/*
 * Name: get_alias_hash_value
 * 
 * Description: adds the ASCII values of the file letters
 * and mods by the hashtable size to get the hash value
 */

inline int get_alias_hash_value(char *file)
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
 * Name: add_cp_url
 *
 * Description: add an entry to `codepage by url' hash table.
 */
#ifdef USE_NLS
void add_cp_url(char *fakename, char *codepage)
{
  int hash;
  alias *old, *new;
	
	if (fakename[strlen(fakename)-1]=='/') 
		fakename[strlen(fakename)-1]=0;
  hash = get_alias_hash_value(fakename);
	
	DBG(printf("add_cp_url('%s','%s')\n",fakename,codepage);)
  old = cp_url_hashtable[hash];

  if (old)
    while (old->next) {
      if (!strcmp(fakename, old->fakename)) /* dont' add twice */
        return;
      old = old->next;
    }
  new = (alias *) malloc(sizeof(alias));
  if (!new)
    die(OUT_OF_MEMORY);

  if (old)
    old->next = new;
  else
    cp_url_hashtable[hash] = new;

  new->fakename = strdup(fakename);
  new->fake_len = strlen(fakename);
  new->realname = strdup(codepage);
  new->real_len = strlen(codepage);

  new->next = NULL;
}
#endif

/*
 * Name: add_alias
 *
 * Description: add an Alias, Redirect or ScriptAlias to the 
 * alias hash table.
 */

void add_alias(char *fakename, char *realname, int type)
{
	int hash;
	alias *old, *new;
	hash = get_alias_hash_value(fakename);

	old = alias_hashtable[hash];

	if (old)
		while (old->next) {
			if (!strcmp(fakename, old->fakename))	/* dont' add twice */
				return;
			old = old->next;
		}
	new = (alias *) malloc(sizeof(alias));
	if (!new)
		die(OUT_OF_MEMORY);

	if (old)
		old->next = new;
	else
		alias_hashtable[hash] = new;

	new->fakename = strdup(fakename);
	new->fake_len = strlen(fakename);
	new->realname = strdup(realname);
	new->real_len = strlen(realname);

	new->type = type;
	new->next = NULL;
}

/*
 * Name: chroot_aliases
 *
 * Description: Translates aliases after chrooting boa.
 */
void chroot_aliases()
{
  int hash;
  alias *a;

	DBG(printf("chroot_aliases (root=%s)\n",server_chroot);)	
	if (!server_chroot)
		return;

	for (hash=0;hash<ALIAS_HASHTABLE_SIZE;hash++)
	{
	  a = alias_hashtable[hash];

	  if (a)
	    while (a) {
		  if (a->type!=REDIRECT) {
		      if (!strncmp(a->realname,server_chroot,strlen(server_chroot)))
					{
						strcpy(a->realname,a->realname + strlen(server_chroot));
					}else
					{
#ifdef BOA_TIME_LOG
						log_error_time();
						fprintf(stderr,"Warning: Alias %s unaccessible from %s\n",
								a->realname,server_chroot);
#endif
						syslog(LOG_ERR, "Warning: Alias %s unaccessible from %s\n", a->realname, server_chroot);
					}
		  }
	      a = a->next;
	    }
	}
}


/*
 * Name: translate_uri
 * 
 * Description: Parse a request's virtual path.  Sets path_info,
 * query_string, pathname, and script_name data if it's a 
 * ScriptAlias or a CGI.  Note -- this should be broken up.
 * 
 * Return values: 
 *   0: failure, close it down
 *   1: success, continue 
 *
 * Note: If virtual server (directory) doesn't exist, boa returns 404 :-(
 */

int translate_uri(request * req)
{
	char buffer[(2*MAX_HEADER_LENGTH) + 1];  /* by martin@tdp.cz */
	char *req_urip;
	alias *current;
	int is_nph = 0;
	char c, *p;
	int hash;
	char *docroot;

	/* Percent-decode request */
	if (unescape_uri(req->request_uri) == 0) {
#ifdef BOA_TIME_LOG
		log_error_doc(req);
		fputs("Problem unescaping uri\n", stderr);
#endif
		syslog(LOG_ERR, "Problem unescaping uri");
		send_r_bad_request(req);
		return 0;
	}

	/* clean pathname */
	clean_pathname(req->request_uri);
	
	/* Move anything after ? into req->query_string */

	req_urip = req->request_uri;
	if (req_urip[0] != '/') {
		send_r_not_found(req);
		return 0;
	}
	
	/* This is probably wrong, because if you access /test/nph-xxx/no-nph.cgi,
		 it's processed as nph... <martin@tdp.cz> */
	while ((c = *req_urip) && c != '?') {
		req_urip++;
		if (c == '/') {
			if (strncmp("nph-", req_urip, 4) == 0)
				is_nph = 1;
			else
				is_nph = 0;
		}
	}

	if (c == '?') {
		*req_urip++ = '\0';
		req->query_string = strdup(req_urip);
	}
	
#ifdef USE_NLS
  /* Find codepage `alias' */
  hash = get_alias_hash_value(req->request_uri);
  current = cp_url_hashtable[hash];
  while (current) {
    if (!memcmp(req->request_uri, current->fakename,
          current->fake_len)) {
      if (current->fakename[current->fake_len - 1] != '/' &&
        req->request_uri[current->fake_len] != '/' &&
        req->request_uri[current->fake_len] != '\0') {
        break;
      }
			strcpy(req->request_uri,&req->request_uri[current->fake_len]); 
			req->cp_name = current->realname;
			break;
		}
		current = current->next;
	}
#endif		
	

	/* Find ScriptAlias, Alias, or Redirect */
	hash = get_alias_hash_value(req->request_uri);

	current = alias_hashtable[hash];
	while (current) {
		if (!memcmp(req->request_uri, current->fakename,
					current->fake_len)) {
			if (current->fakename[current->fake_len - 1] != '/' &&
				req->request_uri[current->fake_len] != '/' &&
				req->request_uri[current->fake_len] != '\0') {
				break;
			}
			if (current->type == SCRIPTALIAS) {		/* Script */
				if (is_nph)
					req->is_cgi = NPH;
				else
					req->is_cgi = CGI;
				return init_script_alias(req, current);
			}
			
			sprintf(buffer, "%s%s", current->realname,
					&req->request_uri[current->fake_len]);

			if (current->type == REDIRECT) {	/* Redirect */
				send_redirect_temp(req, buffer);
				return 0;
			} else {		/* Alias */
				req->pathname = strdup(buffer);
				return 1;
			}
		}
		current = current->next;
	}

	/* No Aliasing done... try userdir */
	if (user_dir && req->request_uri[1] == '~') {
		char *user_homedir;

		req_urip = req->request_uri + 2;

		p = strchr(req_urip, '/');
		if (p)
			*p = '\0';

		user_homedir = get_home_dir(req_urip);
		if (p) /* have to restore request_uri in case of error */
			*p = '/';	
								   
		if (!user_homedir) {	/*no such user */
			send_r_not_found(req);
			return 0;
		}
		
		/* URI length check to prevent crashing */
		if (strlen(user_homedir) + 1 + strlen(user_dir) + (p ? strlen(p) : 0)
				> MAX_HEADER_LENGTH) {
			log_error_doc(req);
			syslog(LOG_ERR, "uri too long!\n");
			send_r_bad_request(req);
			return 0;
		}
				
		sprintf(buffer, "%s/%s", user_homedir, user_dir);
		if (p)
			strcat(buffer, p);
	} else { 	/* no aliasing, no userdir... */
    if (virtualhost) {
			docroot=0;
     if (req->host)                                 /* HTTP 'Host:' sent */
			 docroot = get_virtual_host(req->host);
		 if (!docroot) {
			 free(req->host);
			 req->host = NULL;
			 if (req->local_ip_addr)
				 docroot = get_virtual_host(req->local_ip_addr);
			}
		 if (!docroot)
			  docroot = document_root;
		 else
			 if (!req->host)
				 req->host = strdup(req->local_ip_addr);
   }else
		 docroot = document_root;
	 	sprintf(buffer, "%s%s", docroot, req->request_uri);
	}

	req->pathname = strdup(buffer);

	if (strcmp(CGI_MIME_TYPE, get_mime_type(buffer)) == 0) {	/* cgi */
		if (is_nph)
			req->is_cgi = NPH;
		else
			req->is_cgi = CGI;
		req->script_name = strdup(req->request_uri);
		return 1;
	} else if (req->method == M_POST) {		/* POST to non-script */
		send_r_not_implemented(req);
		return 0;
	} else
		return 1;
}
/*
 * Name: init_script_alias
 * 
 * Description: Performs full parsing on a ScriptAlias request
 * 
 * Return values:
 *
 * 0: failure, shut down
 * 1: success, continue          
 */

int init_script_alias(request * req, alias * current1)
{
	char pathname[MAX_HEADER_LENGTH + 1];
	struct stat statbuf;
	char buffer[MAX_HEADER_LENGTH + 1];

	int index = 0;
	char c;

	sprintf(pathname, "%s%s", current1->realname,
			&req->request_uri[current1->fake_len]);

	index = current1->real_len;

	do {
		c = pathname[++index];
	} while (c != '/' && c != '\0');

	if (c == '/') { /* path_info... still have to check for query */
		int hash;
		alias * current;

		req->path_info = strdup(pathname + index);
		pathname[index] = '\0'; /* kill path_info from path */

		hash = get_alias_hash_value(req->path_info);
		current = alias_hashtable[hash];
		while (current && !req->path_translated) {
			if (!strncmp(req->path_info, current->fakename,
					current->fake_len)) {
				sprintf(buffer, "%s%s", current->realname,
						&req->path_info[current->fake_len]);
				req->path_translated = strdup(buffer);
			}
			current = current->next;
		}
		/* no alias... try userdir */
		if (!req->path_translated && user_dir && 
				req->path_info[1] == '~') {
			char *user_homedir;
			char *p;

			p = strchr(pathname + index + 1, '/');
			if (p)
				*p = '\0';

			user_homedir = get_home_dir(pathname + index + 2);
			if (p)
				*p = '/';

			if(!user_homedir) { /* no such user */
				send_r_not_found(req);
				return 0;
			}
			sprintf(buffer, "%s/%s", user_homedir, user_dir);
			if (p) 
				strcat(buffer, p);
			req->path_translated = strdup(buffer);
		}

		if (!req->path_translated) { 
			/* no userdir, no aliasing... stock */
			sprintf(buffer, "%s%s", document_root,
					req->path_info);
			req->path_translated = strdup(buffer);
		}
	}

	if (stat(pathname, &statbuf) == -1) {
		send_r_not_found(req);
		return 0;
	} else if (!S_ISREG(statbuf.st_mode) || 
			access(pathname, R_OK | X_OK) == -1) {
		send_r_forbidden(req);
		return 0;
	}

	req->pathname = strdup(pathname);

	/* there used to be some ip stuff in here */

  /* This AFAIK doesn't work! <martin@tdp.cz> */
	/* req->script_name = strdup(pathname-current1->fake_len-1); */
	req->script_name = strdup(req->request_uri); 

	return 1;
}

void dump_alias(void)
{
	int i;
	alias *temp;

	for (i = 0; i < ALIAS_HASHTABLE_SIZE; ++i) {	/* these limits OK? */
		if (alias_hashtable[i]) {
			temp = alias_hashtable[i];
			while (temp) {
				alias *temp_next;

				if (temp->fakename)
					free(temp->fakename);
				if (temp->realname)
					free(temp->realname);
				temp_next = temp->next;
				free(temp);
				temp = temp_next;
			}
			alias_hashtable[i] = NULL;
		}
	}
}
