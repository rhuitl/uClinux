#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <errno.h>

int
getdomainname(char *name, size_t len)
{
  struct utsname uts;

  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (uname(&uts) == -1) return -1;

  if (strlen(uts.domainname)+1 > len) {
    errno = EINVAL;
    return -1;
  }
  strcpy(name, uts.domainname);
  return 0;
}
