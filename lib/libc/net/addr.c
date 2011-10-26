/* Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
 * This file is part of the Linux-8086 C library and is distributed
 * under the GNU Library General Public License.
 */

#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#ifdef L_inet_aton
int
inet_aton(cp, inp)
const char *cp;
struct in_addr *inp;
{
  unsigned long addr;
  int value;
  int part;

  if (!inp)
    return 0;
  
  addr = 0;
  for (part=1;part<=4;part++) {

    if (!isdigit(*cp))
      return 0;
        
    value = 0;
    while (isdigit(*cp)) {
      value *= 10;
      value += *cp++ - '0';
      if (value > 255)
        return 0;
    }
    
    if (*cp++ != ((part == 4) ? '\0' : '.'))
      return 0;
    
    addr <<= 8;
    addr |= value;
  }
  
  inp->s_addr = htonl(addr);

  return 1;
}
#endif

#ifdef L_inet_addr
unsigned long
inet_addr(cp)
const char *cp;
{
  struct in_addr a;
  if (!inet_aton(cp, &a))
    return -1;
  else
    return a.s_addr;
}
#endif

#ifdef L_inet_ntoa

extern char * itoa(int);  

char *
inet_ntoa(in)
struct in_addr in;
{
  static char buf[18];
  unsigned long addr = ntohl(in.s_addr);
  
  strcpy(buf, itoa((addr >> 24) & 0xff));
  strcat(buf, ".");
  strcat(buf, itoa((addr >> 16) & 0xff));
  strcat(buf, ".");
  strcat(buf, itoa((addr >> 8) & 0xff));
  strcat(buf, ".");
  strcat(buf, itoa(addr & 0xff));
  
  return buf;
}

#endif

#ifdef L_inet_ntop

char *
inet_ntop(af, src, dst, cnt)
int af;
const void *src;
char *dst;
size_t cnt;
{
  char *lp;
  if (af == AF_INET) {
	lp = inet_ntoa(*((struct in_addr *) src));
	memcpy(dst, lp, cnt);
#ifdef AF_INET6
  } else if (af == AF_INET6) {
	memcpy(dst, "AF_INET6", cnt);
#endif
  } else {
	dst = NULL;
  }
  return(dst);
}

#endif

#ifdef L_inet_pton

/* int
 * inet_pton4(src, dst)
 *      like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *      1 if `src' is a valid dotted quad, else 0.
 * notice:
 *      does not touch `dst' unless it's returning 1.
 * author:
 *      Paul Vixie, 1996.
 */
static int
inet_pton4(src, dst)
        const char *src;
        u_char *dst;
{
        int saw_digit, octets, ch;
        u_char tmp[4], *tp;

        saw_digit = 0;
        octets = 0;
        *(tp = tmp) = 0;
        while ((ch = *src++) != '\0') {

                if (ch >= '0' && ch <= '9') {
                        u_int new = *tp * 10 + (ch - '0');

                        if (new > 255)
                                return (0);
                        *tp = new;
                        if (! saw_digit) {
                                if (++octets > 4)
                                        return (0);
                                saw_digit = 1;
                        }
                } else if (ch == '.' && saw_digit) {
                        if (octets == 4)
                                return (0);
                        *++tp = 0;
                        saw_digit = 0;
                } else
                        return (0);
        }
        if (octets < 4)
                return (0);
        memcpy(dst, tmp, 4);
        return (1);
}

/* int
 *  * inet_pton6(src, dst)
 *      convert presentation level address to network order binary form.
 * return:
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *      (1) does not touch `dst' unless it's returning 1.
 *      (2) :: in a full address is silently ignored.
 * credit:
 *      inspired by Mark Andrews.
 * author:
 *      Paul Vixie, 1996.
 */

#ifdef INET_IPV6

static int
inet_pton6(src, dst)
        const char *src;
        u_char *dst;
{
        static const char xdigits[] = "0123456789abcdef";
        u_char tmp[16], *tp, *endp, *colonp;
        const char *curtok;
        int ch, saw_xdigit;
        u_int val;


        tp = memset(tmp, '\0', 16);
        endp = tp + 16;
        colonp = NULL;
        /* Leading :: requires some special handling. */
        if (*src == ':')
                if (*++src != ':')
                        return (0);
        curtok = src;
        saw_xdigit = 0;
        val = 0;
        while ((ch = tolower (*src++)) != '\0') {
                const char *pch;

                pch = strchr(xdigits, ch);
                if (pch != NULL) {
                        val <<= 4;
                        val |= (pch - xdigits);
                        if (val > 0xffff)
                                return (0);
                        saw_xdigit = 1;
                        continue;
                }
                if (ch == ':') {
                        curtok = src;
                        if (!saw_xdigit) {
                                if (colonp)
                                        return (0);
                                colonp = tp;
                                continue;
                        } else if (*src == '\0') {
                                return (0);
                        }
                        if (tp + 2 > endp)
                                return (0);
                        *tp++ = (u_char) (val >> 8) & 0xff;
                        *tp++ = (u_char) val & 0xff;
                        saw_xdigit = 0;
                        val = 0;
                        continue;
                }
                if (ch == '.' && ((tp + 4) <= endp) &&
                    inet_pton4(curtok, tp) > 0) {
                        tp += 4;
                        saw_xdigit = 0;
                        break;  /* '\0' was seen by inet_pton4(). */
                }
                return (0);
        }
        if (saw_xdigit) {
                if (tp + 2 > endp)
                        return (0);
                *tp++ = (u_char) (val >> 8) & 0xff;
                *tp++ = (u_char) val & 0xff;
        }
        if (colonp != NULL) {
                /*
                 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
                const int n = tp - colonp;
                int i;

                if (tp == endp)
                        return (0);
                for (i = 1; i <= n; i++) {
                        endp[- i] = colonp[n - i];
                        colonp[n - i] = 0;
                }
                tp = endp;
        }
        if (tp != endp)
                return (0);
        memcpy(dst, tmp, 16);
        return (1);
}
#endif /* INET_IPV6 */

/* int
 * inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address wasn't valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *      Paul Vixie, 1996.
 */
extern int
inet_pton(af, src, dst)
	int af;
	const char *src;
	void *dst;
{
	switch (af) {
	case AF_INET:
		return (inet_pton4(src, dst));
#ifdef INET_IPV6
	case AF_INET6:
		return (inet_pton6(src, dst));
#endif
	default:
//		__set_errno (EAFNOSUPPORT);
		return (-1);
	}
	/* NOTREACHED */
}
#endif


#if L_inet_mkadr

/*
 * Formulate an Internet address from network + host.  Used in
 * building addresses stored in the ifnet structure.
 */
struct in_addr
inet_makeaddr(net, host)
        u_int32_t net, host;
{
        u_int32_t addr;

        if (net < 128)
                addr = (net << IN_CLASSA_NSHIFT) | (host & IN_CLASSA_HOST);
        else if (net < 65536)
                addr = (net << IN_CLASSB_NSHIFT) | (host & IN_CLASSB_HOST);
        else if (net < 16777216L)
                addr = (net << IN_CLASSC_NSHIFT) | (host & IN_CLASSC_HOST);
        else
                addr = net | host;
        addr = htonl(addr);
        return (*(struct in_addr *)&addr);
}

#endif

#if L_inet_lnaof
/*
 * Return the local network address portion of an
 * internet address; handles class a/b/c network
 * number formats.
 */
u_int32_t
inet_lnaof(in)
	struct in_addr in;
{
	u_int32_t i = ntohl(in.s_addr);

	if (IN_CLASSA(i))
		return ((i)&IN_CLASSA_HOST);
	else if (IN_CLASSB(i))
		return ((i)&IN_CLASSB_HOST);
	else
		return ((i)&IN_CLASSC_HOST);
}
#endif

#ifdef L_inet_netof

/*
 * Return the network number from an internet
 * address; handles class a/b/c network #'s.
 */
u_int32_t
inet_netof(in)
        struct in_addr in;
{
        u_int32_t i = ntohl(in.s_addr);

        if (IN_CLASSA(i))
                return (((i)&IN_CLASSA_NET) >> IN_CLASSA_NSHIFT);
        else if (IN_CLASSB(i))
                return (((i)&IN_CLASSB_NET) >> IN_CLASSB_NSHIFT);
        else
                return (((i)&IN_CLASSC_NET) >> IN_CLASSC_NSHIFT);
}

#endif
