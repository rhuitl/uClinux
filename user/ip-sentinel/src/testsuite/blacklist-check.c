// $Id: blacklist-check.c,v 1.10 2005/03/29 15:49:58 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003,2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//  
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//  

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "blacklist.h"
#include "arguments.h"
#include "util.h"

#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

struct ether_addr	local_mac_address = { { 127,0,0,1,0,0 } };

int main(int argc, char *argv[])
{
  BlackList		lst;
  FILE *		ip_file;
  FILE *		result_file;
  struct Arguments	args = {
    .mac = { .type  = mcRANDOM },
    .ipfile    = argv[2]
  };

  if (argc!=4) {
    Vwrite(2, "Wrong argument-count; aborting...\n", 33);
    return EXIT_FAILURE;
  }

  ip_file = fopen(argv[1], "r");
  if (ip_file==0) {
    perror("fopen()");
    return EXIT_FAILURE;
  }

  result_file = fopen(argv[3], "r");
  if (result_file==0) {
    perror("fopen()");
    return EXIT_FAILURE;
  }

  
  
  BlackList_init(&lst, &args);
  BlackList_softUpdate(&lst);
  BlackList_print(&lst, 3);
  Vwrite(1, "\n", 1);

  while (!ferror(ip_file) && !feof(ip_file)) {
    char		ip_str[128], mac_str[128];
    int			res_i = fscanf(ip_file,     "%s\n", ip_str);
    int			res_r = fscanf(result_file, "%s\n", mac_str);
    struct ether_addr	atmac;
    struct ether_addr	exp_result;
    struct in_addr	inp;
    bool		is_ok = 1;
    char *		at_pos;
    struct ether_addr const	*result;
    struct BlackListQuery	query = {
      .ip  = &inp,
      .mac = &atmac,
    };

    if (ip_str[0]=='#' || ip_str[0]=='\n' || ip_str[0]=='\0') continue;
    
    if (res_i==0 || res_r==0) {
      Vwrite(2, "Invalid format; aborting...\n", 28);
      return EXIT_FAILURE;
    }

    if ((at_pos=strchr(ip_str, ','))!=0) {
      *at_pos = '\0';
      if (ether_aton_r(at_pos+1, &atmac)==0) {
	Vwrite(2, "Invalid MAC in input-file...\n", 29);
	return EXIT_FAILURE;
      }
    }
    else {
      ether_aton_r("ff:ff:ff:ff:ff:00", &atmac);
    }

    if (inet_aton(ip_str, &inp)==0) {
      Vwrite(2, "Invalid IP; aborting...\n", 24);
      return EXIT_FAILURE;
    }

    if (mac_str[0]!='-' && mac_str[0]!='R' &&
	ether_aton_r(mac_str, &exp_result)==0)
    {
      Vwrite(2, "Invalid MAC; aborting...\n", 25);
      return EXIT_FAILURE;
    }

    printf("%-15s\t", ip_str);
    if ((result=BlackList_getMac(&lst, &query))!=0) {
      char		buffer[128];
      sprintf(buffer, "%s", ether_ntoa(result));
      if (mac_str[0]=='-') is_ok = 0;
      else if (mac_str[0]!='R') {
	strcat(buffer, "/");
	strcat(buffer, ether_ntoa(&exp_result));
	is_ok = is_ok && (memcmp(result, &exp_result, sizeof *result)==0);
	if (query.poison_mac) {
	  strcat(buffer, "|");
	  strcat(buffer, ether_ntoa(query.poison_mac));
	}
      }
      printf("%-35s\t", buffer);
    }
    else {
      printf("%-35s\t", "not found");
      is_ok = is_ok && (mac_str[0]=='-');
    }

    if (is_ok) printf("OK\n");
    else       printf("FAIL\n");
  }

  BlackList_free(&lst);
  fclose(result_file);
  fclose(ip_file);
  
  return EXIT_SUCCESS;  
}


  /// Local Variables:
  /// compile-command: "make -C .. check"
  /// End:
