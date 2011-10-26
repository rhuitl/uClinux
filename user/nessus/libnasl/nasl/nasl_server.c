/* Nessus Attack Scripting Language 
 *
 * Copyright (C) 2004 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <includes.h>

#include "nasl.h"
#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "preparse.h"

#ifdef ENABLE_PLUGIN_SERVER

#define UX_SOCKET_PATH NESSUS_STATE_DIR"/nessus/plugin_server"
#define UX_PID_PATH    NESSUS_STATE_DIR"/nessus/plugin_server.pid"
#define NUM_CLIENTS	99 	/* Quite arbitrary indeed */

struct nasl_idx_entry {
	char * fname;
	unsigned long offset;
	unsigned long data_len;
	};

struct nasl_idx {
	struct nasl_idx_entry * entries;
	int num_entries;
	int num_alloc_entries;

	char * data;
	int data_sz;
	int data_ptr;
};

static struct nasl_idx  * idx = NULL;

static int qsort_helper(const void * a, const void * b)
{
 struct nasl_idx_entry * a1, *b1;

 a1 = (struct nasl_idx_entry * ) a;
 b1 = (struct nasl_idx_entry * ) b;
 return strcmp(a1->fname, b1->fname);
}

static void handle_sigterm()
{
 unlink(UX_SOCKET_PATH);
 unlink(UX_PID_PATH);
 _exit(0);
}

/*----------------------------------------------------------------------------*/


static int mklistener()
{
 struct sockaddr_un addr;
 int soc;
 int one = 1;
 
 unlink(UX_SOCKET_PATH);

 soc = socket(AF_UNIX, SOCK_STREAM, 0);
 if(soc < 0)
  return -1;

 
 bzero(&addr, sizeof(addr));
 addr.sun_family = AF_UNIX;
 bcopy(UX_SOCKET_PATH, addr.sun_path, strlen(UX_SOCKET_PATH));
 setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
 if(bind(soc, (struct sockaddr*)(&addr), sizeof(addr)) == -1)
 {
  perror("nasl_cache.c:mklistener():bind ");
  close(soc);
  return -1;
 }
 chmod(UX_SOCKET_PATH, 0700);
 if(listen(soc, NUM_CLIENTS - 1) < 0)
  {
  perror("nasl_cache.c:mklistener():listen ");
  close(soc);
  return -1;
  }

 return soc;
}



static int _nasl_index_fetch(char * fname, int start, int end)
{
 int mid;
 int cmp;

 if ( start == end ) 
	{
	if ( strcmp(idx->entries[start].fname, fname) == 0 )
		return start;
	else
		return -1;
	}

 mid = (start + end ) / 2;
 cmp = strcmp(idx->entries[mid].fname, fname);
 if ( cmp == 0 ) return mid;
 else if ( cmp > 0 ) return _nasl_index_fetch(fname, start, mid);
 else return _nasl_index_fetch(fname, mid + 1, end);
}


int nasl_index_fetch(char * fname, char ** result, int * res_sz)
{
 int soc;
 struct sockaddr_un soca;
 int len = sizeof(soca);
 int tot_len;
 char * buf;
 struct stat st;

 if ( stat(UX_SOCKET_PATH, &st) < 0 )
	return -1;
 

 soc = socket ( AF_UNIX, SOCK_STREAM, 0 );
 if ( soc < 0 )
  return -1;

 bzero(&soca, sizeof(soca));
 soca.sun_family = AF_UNIX;
 bcopy(UX_SOCKET_PATH, soca.sun_path, strlen(UX_SOCKET_PATH));
 if ( connect ( soc, (struct sockaddr * )&soca, len ) < 0 )  
 {
  perror("Could not connect to the plugins server ");
  return -1;
 }


 len = strlen(fname);
 send(soc, &len, sizeof(len), 0);
 send(soc, fname, len, 0 );
 recv(soc, &tot_len, sizeof(tot_len), 0);
 *res_sz = tot_len;
 
 if ( tot_len > 0 )
 {
  int n = 0;
  buf = emalloc(tot_len);
  while ( n != tot_len )
   {
   int e = recv(soc, buf + n , tot_len - n , 0);
   if ( e <= 0 && errno != EINTR ) { efree(&buf); close (soc); return -1; }
   if ( e > 0 ) n += e;
   }
 }
 else 
  buf = NULL;

 close ( soc );
 *result = buf;
 return tot_len > 0 ? tot_len : -1;
}

static int internal_nasl_index_fetch(char * fname, char ** result, int * res_sz )
{
 int w;

 *res_sz = 0;

 if ( idx == NULL )
	return -1;


 w = _nasl_index_fetch(fname, 0, idx->num_entries);

 if ( w < 0 ) return -1;
 *res_sz = idx->entries[w].data_len;
 *result = &(idx->data[idx->entries[w].offset]);
 return *res_sz;
}


int process(int soc)
{
 int clnt;
 struct sockaddr_un soca;
 int len = sizeof(soca);

 clnt = accept(soc, (struct sockaddr*)&soca, &len);
 if ( clnt > 0 )
 {
  int len = 0;
  char name[1024];
  char * result;
  int n;
  if ( recv(clnt, &len, sizeof(len), 0) < sizeof(len) || len >= sizeof(name) ) 
	{
	close(clnt);
	return -1;
	}


  bzero(name, sizeof(name));
	 
  if ( recv(clnt, name, len, 0 ) < len )
	{
	close(clnt);
	return -1;
	}

  if ( internal_nasl_index_fetch(name, &result, &len) < 0 )
	len = 0;

  send(clnt, &len, sizeof(len), 0);
  if ( len > 0 ) {
	n = 0;
	while ( n != len )
	{
	int e = send(clnt, result + n, len - n, 0);
	if ( e < 0 && errno != EINTR ) { close(clnt); return -1; }
	else if ( e > 0 ) n += e;
	}
   }
  close(clnt);
  return 0;
 }
 return -1;
}

pid_t _nasl_server_start(char * plugin_directory, char * cache_directory, int no_daemon)
{
 DIR * dir;
 struct dirent * de;
 char full_name[2048];
 char cwd[2048];
 struct stat st;
 pid_t pid;

 if ( no_daemon == 0 )
  {
  int fd; 
  fd = open(UX_PID_PATH, O_RDONLY);
  if ( fd >= 0 )
  {
   char buf[1024];
   int pid;
   read(fd, buf, sizeof(buf) - 1 );
   buf[sizeof(buf) - 1 ] = '\0';
   pid = atoi(buf);
   if ( pid ) kill ( pid, SIGKILL );  
   unlink(UX_PID_PATH);
  }
  unlink(UX_SOCKET_PATH);
 }

 mkdir(cache_directory, 0755);
 cwd[sizeof(cwd) - 1] = '\0';
 getcwd(cwd, sizeof(cwd) - 1);
 chdir(plugin_directory);

 if ( idx != NULL ) 
 {
  efree(&idx);
 }


 dir = opendir(plugin_directory);
 if ( dir == NULL )
 {
  perror(plugin_directory);
  chdir(cwd);
  return -1;
 }
 
 while ( ( de = readdir(dir) ) != NULL )
 {
  if ( de->d_name[0] != '.' )
  {
   char * sfx = strrchr(de->d_name, '.');
   if ( sfx != NULL && strcmp(sfx, ".nasl")  == 0 )
   {
    snprintf(full_name, sizeof(full_name), "%s/%s", plugin_directory, de->d_name);
    if (nasl_parse_and_dump(full_name, de->d_name, cache_directory) < 0 )
        {
        perror("nasl_parse_and_dump failed");
	continue;
        }
   }
  }
 }
 closedir(dir);
 if ( no_daemon != 0 ) return 0;


 /*----------------------------------------*/

 if ( (pid = fork()) == 0 )
 {
 int lst;
 int fd;
 char buf[256];

 signal(SIGTERM, handle_sigterm);
 setproctitle("nasl plugins server");

 fd = open(UX_PID_PATH, O_CREAT|O_TRUNC|O_WRONLY, 0644);
 snprintf(buf, sizeof(buf), "%d", getpid());
 write(fd, buf, strlen(buf));
 close(fd);
  
 idx = emalloc ( sizeof(struct nasl_idx));

 idx->num_alloc_entries = 512;
 idx->num_entries = 0;
 idx->entries = emalloc(idx->num_alloc_entries * sizeof ( struct nasl_idx_entry ));

 idx->data_sz     = 1024;
 idx->data_ptr    = 0;
 idx->data  	  = emalloc(idx->data_sz);


 
 
 dir = opendir(cache_directory);
 if ( dir == NULL )
 { 
  perror(cache_directory);
  chdir(cwd);
  return -1;
 }



 while (  (de = readdir(dir)) != NULL )
 {
   if ( de->d_name[0] != '.'  && strstr(de->d_name, ".nasl") != NULL )
   {
    int fd;
    struct stat st;
    unsigned int len, n = 0;

    snprintf(full_name, sizeof(full_name), "%s/%s", cache_directory, de->d_name);
    fd = open(full_name, O_RDONLY);
    if ( fd < 0 )
     {
	perror("open ");
	continue;
     }
    
    /* Copy the file content in memory */
    if( fstat(fd, &st) < 0 )
    {
      perror("fstat ");
      continue;
    }

    len = (unsigned int)st.st_size;
    if ( idx->data_sz <= idx->data_ptr + len )
    {
     idx->data_sz *= 2;
     if ( idx->data_sz < idx->data_ptr + len ) 
	idx->data_sz += idx->data_ptr + len;

     idx->data = erealloc(idx->data, idx->data_sz);
    }

    n = 0;
    while ( n != len )
    {
     int e;
     e = read (fd, idx->data + idx->data_ptr + n, len - n );
     if ( e < 0 && errno != EINTR ) 
	{
	close(fd);
	break;	
	}
     else if ( e > 0 ) n += e;
    }

    close(fd);

    /* Add the file ref in our index */
    if ( idx->num_entries >= idx->num_alloc_entries )
    {
      idx->num_alloc_entries *= 2;
      idx->entries = erealloc( idx->entries, idx->num_alloc_entries * sizeof(struct nasl_idx_entry ) );
    }
    idx->entries[idx->num_entries].fname  = strdup(de->d_name);
    idx->entries[idx->num_entries].offset = idx->data_ptr;
    idx->entries[idx->num_entries].data_len    = len;
    idx->num_entries ++;
    idx->data_ptr += len;
   }
 }

 idx->data = erealloc(idx->data, idx->data_ptr);
 idx->data_sz = idx->data_ptr;
 closedir(dir);
 qsort(idx->entries, idx->num_entries, sizeof(struct nasl_idx_entry), qsort_helper);
 chdir(cwd);
 lst = mklistener();
 if ( lst < 0 ) 
	{
	 unlink(UX_SOCKET_PATH);
	 unlink(UX_PID_PATH);
 	 exit(1);
	}

 for ( ;; ) process(lst);
 }

 /*----------------*/
 if ( pid > 0 )
 {
  /* Wait for the server to parse every plugin */
  while ( stat(UX_SOCKET_PATH, &st ) < 0 )  usleep(5000);
 }

 return pid;
}
pid_t nasl_server_start(char * plugin_directory, char * cache_directory)
{
 return _nasl_server_start(plugin_directory, cache_directory, 0);
} 

void nasl_server_recompile(char * plugin_directory, char * cache_directory)
{
 _nasl_server_start(plugin_directory, cache_directory, 1);
}

#endif
