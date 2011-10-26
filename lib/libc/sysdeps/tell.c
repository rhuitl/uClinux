#include <unistd.h>

off_t tell(int);

off_t
tell (int fildes)
{
  return lseek (fildes, 0, SEEK_CUR);
}
