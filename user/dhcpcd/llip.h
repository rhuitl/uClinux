#ifndef __llip_h_defined_
#define IN
#define OUT

/* sets up on the network interface specified by ifname an appropriate 
   link local (auto IP) address. It is within the range of 169.254.1.0
   - 169.254.254.255 and netmask of 16 bits. The function tries to setup
   the ip address such that the last two bytes of the ip address match
   the last two bytes of the MAC address for that interface. This should
   help users in guessing their IP address and set up some stability in
   ip address assignments. If the IP address desired according to the last
   two bytes of the MAC address is in use the function sets the interface
   up on a random address.
*/ 
int setup_link_local_if(IN char *ifname, OUT unsigned int *addr_assigned);

#endif
