
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <malloc.h>

#define DEV	"/dev"

char *
ttyname(fd)
int   fd;
{
   struct stat st, dst;
   DIR  *fp;
   struct dirent *d;
   static char *name;
   int noerr = errno;

   if (fstat(fd, &st) < 0)
      return NULL;
   if (!isatty(fd))
   {
      errno = ENOTTY;
      return NULL;
   }
   
   if (name == NULL)
   {
      name = malloc(sizeof(char) * NAME_MAX);
      if (name == NULL)
      {
	 errno = ENOMEM;
	 return NULL;
      }
   }

   fp = opendir(DEV);
   if (fp == 0)
      return NULL;
   strcpy(name, DEV);
   strcat(name, "/");

   while ((d = readdir(fp)) != 0)
   {
      strcpy(name + sizeof(DEV), d->d_name);
      if (stat(name, &dst) == 0
         && st.st_dev == dst.st_dev && st.st_ino == dst.st_ino)
      {
	 closedir(fp);
	 errno = noerr;
	 return name;
      }
   }
   closedir(fp);
   errno = noerr;
   return NULL;
}
