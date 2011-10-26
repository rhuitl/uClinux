
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

/*
 * These functions find the absolute path to the current working directory.
 *
 * They don't use large amounts of stack space and only use malloc if the
 * buf argument is NULL.
 */

static char * recurser();	/* Routine to go up tree */
static char * search_dir();	/* Routine to find the step back down */

static struct GCWDvars_s {
	char 		*S_path_buf;
	int   		 S_path_size;
	dev_t		 S_root_dev;
	ino_t		 S_root_ino;
	struct stat	 S_st;
} *GCWDvars;

#define path_buf	(GCWDvars->S_path_buf)
#define path_size	(GCWDvars->S_path_size)
#define root_dev	(GCWDvars->S_root_dev)
#define root_ino	(GCWDvars->S_root_ino)
#define st		(GCWDvars->S_st)

char *
getcwd(buf, size)
char * buf;
size_t size;
{
   char *res;

   GCWDvars = malloc(sizeof(struct GCWDvars_s));
   if (GCWDvars == NULL)
      return NULL;

   /* Unfortunately, the man page says we can accept a NULL first arg which
    * means allocate the memory...
    */
   if (buf == NULL) {
      if (size <= 0) size = PATH_MAX;
      path_buf = malloc(size);
   } else
      path_buf = buf;
   path_size = size;

   if( size < 3 ) { errno = ERANGE; return NULL; }
   strcpy(path_buf, ".");

   if( stat("/", &st) < 0 ) return NULL;

   root_dev = st.st_dev;
   root_ino = st.st_ino;

   res = recurser();
   free(GCWDvars);
   return res;
}

static char *
recurser()
{
   dev_t this_dev;
   ino_t this_ino;
   if( stat(path_buf, &st) < 0 ) return NULL;
   this_dev = st.st_dev;
   this_ino = st.st_ino;
   if( this_dev == root_dev && this_ino == root_ino )
   {
      strcpy(path_buf, "/");
      return path_buf;
   }
   if( strlen(path_buf) + 4 > path_size ) { errno = ERANGE; return NULL; }
   strcat(path_buf, "/..");
   if( recurser() == 0 ) return NULL;

   return search_dir(this_dev, this_ino);
}

static char *
search_dir(this_dev, this_ino)
dev_t this_dev;
ino_t this_ino;
{
   DIR * dp;
   struct dirent * d;
   char * ptr;
   int slen;
   /* The test is for ELKS lib 0.0.9, this should be fixed in the real kernel*/
   int slow_search = (sizeof(ino_t) != sizeof(d->d_ino));

   if( stat(path_buf, &st) < 0 ) return NULL;
   if( this_dev != st.st_dev ) slow_search = 1;

   slen = strlen(path_buf);
   ptr = path_buf + slen -1;
   if( *ptr != '/' )
   {
      if( slen + 2 > path_size ) { errno = ERANGE; return NULL; }
      strcpy(++ptr, "/");
      slen++;
   }
   slen++;

   dp = opendir(path_buf);
   if( dp == 0 ) return NULL;

   while( (d=readdir(dp)) != 0 )
   {
      if( slow_search || this_ino == d->d_ino )
      {
         if( slen + strlen(d->d_name) > path_size )
	    { errno = ERANGE; return 0; }
         strcpy(ptr+1, d->d_name);
	 if( stat(path_buf, &st) < 0 ) 
	    continue;
         if( st.st_ino == this_ino && st.st_dev == this_dev )
	 {
	    closedir(dp);
	    return path_buf;
	 }
      }
   }

   closedir(dp);
   errno = ENOENT;
   return NULL;
}
