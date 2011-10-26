
/***************************************************************************
 * nbase_rnd.c -- Some simple routines for obtaining random numbers for    *
 * casual use.  These are pretty secure on systems with /dev/urandom, but  *
 * falls back to poor entropy on systems without such support.             *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2006 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://insecure.org/nmap/ to download Nmap.                             *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included Copying.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one the            *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/* $Id: nbase_rnd.c 3899 2006-08-29 05:42:35Z fyodor $ */

#include "nbase.h"
#include <string.h>
#include <stdio.h>
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

int get_random_bytes(void *buf, int numbytes) {
  static char bytebuf[2048];
  static char badrandomwarning = 0;
  static int bytesleft = 0;
  int tmp;
  int res;
  struct timeval tv;
  FILE *fp = NULL;
  unsigned int i;
  short *iptr;
  
  if (numbytes < 0 || numbytes > 0xFFFF) return -1;
  
  if (bytesleft == 0) {
    fp = fopen("/dev/arandom", "r");
    if (!fp) fp = fopen("/dev/urandom", "r");
    if (!fp) fp = fopen("/dev/random", "r");
    if (fp) {
      res = (int) fread(bytebuf, 1, sizeof(bytebuf), fp);
      if (res != sizeof(bytebuf)) {    
	fprintf(stderr, "Failed to read from /dev/urandom or /dev/random\n");
	fclose(fp);
	fp = NULL;
      }      
      bytesleft = sizeof(bytebuf);
    }
    if (!fp) {  
      if (badrandomwarning == 0) {
	badrandomwarning++;
	/*      error("WARNING: your system apparently does not offer /dev/urandom or /dev/random.  Reverting to less secure version."); */
	
	/* Seed our random generator */
	gettimeofday(&tv, NULL);
	srand((tv.tv_sec ^ tv.tv_usec) ^ getpid());
      }
      
      for(i=0; i < sizeof(bytebuf) / sizeof(short); i++) {
	iptr = (short *) ((char *)bytebuf + i * sizeof(short));
	*iptr = rand();
      }
      bytesleft = (sizeof(bytebuf) / sizeof(short)) * sizeof(short);
      /*    ^^^^^^^^^^^^^^^not as meaningless as it looks  */
    } else fclose(fp);
  }
  
  if (numbytes <= bytesleft) { /* we can cover it */
    memcpy(buf, bytebuf + (sizeof(bytebuf) - bytesleft), numbytes);
    bytesleft -= numbytes;
    return 0;
  }
  
  /* We don't have enough */
  memcpy(buf, bytebuf + (sizeof(bytebuf) - bytesleft), bytesleft);
  tmp = bytesleft;
  bytesleft = 0;
  return get_random_bytes((char *)buf + tmp, numbytes - tmp);
}

int get_random_int() {
  int i;
  get_random_bytes(&i, sizeof(int));
  return i;
}

unsigned int get_random_uint() {
  unsigned int i;
  get_random_bytes(&i, sizeof(unsigned int));
  return i;
}

u32 get_random_u32() {
  u32 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

u16 get_random_u16() {
  u16 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

u8 get_random_u8() {
  u8 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

unsigned short get_random_ushort() {
  unsigned short s;
  get_random_bytes(&s, sizeof(unsigned short));
  return s;
}
