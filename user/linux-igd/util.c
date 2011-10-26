#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "globals.h"


static int get_sockfd(void)
{
   static int sockfd = -1;

   if (sockfd == -1)
   {
      if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
      {
         perror("user: socket creating failed");
         return (-1);
      }
   }
   return sockfd;
}

int GetIpAddressStr(char *address, char *ifname)
{
   struct ifreq ifr;
   struct sockaddr_in *saddr;
   int fd;
   int succeeded = 0;

   fd = get_sockfd();
   if (fd >= 0 )
   {
      strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
      ifr.ifr_addr.sa_family = AF_INET;
      if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
      {
         saddr = (struct sockaddr_in *)&ifr.ifr_addr;
         strcpy(address,inet_ntoa(saddr->sin_addr));
         succeeded = 1;
      }
      else
      {
         syslog(LOG_ERR, "Failure obtaining ip address of interface %s", ifname);
         succeeded = 0;
      }
   }
   return succeeded;
}

void trace(int debuglevel, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  if (g_vars.debug>=debuglevel) {
    vsyslog(LOG_DEBUG,format,ap);
  }
  va_end(ap);
}
