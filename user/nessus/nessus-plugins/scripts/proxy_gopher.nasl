#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
#
# This script does not check for CVE-2002-0371 per se,
# but references it as an example of an abuse in the gopher
# protocol. MS advisory MS02-027 also suggests disabling
# the gopher protocol handling completely.
#

if(description)
{ 
 script_id(11305);
 script_bugtraq_id(4930);
 script_cve_id("CVE-2002-0371");
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Proxy accepts gopher:// requests";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The proxy accepts gopher:// requests. 

Gopher is an old network protocol which predates HTTP and
is nearly unused today. As a result, gopher-compatible
software is generally less audited and more likely to contain
security bugs than others.

By making gopher requests, an attacker may evade your firewall
settings, by making connections to port 70, or may even exploit
arcane flaws in this protocol to gain more privileges on this
host (see the attached CVE id for such an example).

Solution : reconfigure your proxy so that it refuses gopher requests.
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if we can use the remote web proxy to do gopher requests"; 
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 
 family["english"] = "Firewalls"; 
 family["francais"] = "Firewalls";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes", "proxy_use.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 3128, 8080);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:3128);
ports = add_port_in_list(list:ports, port:8080);


proxy_use = get_kb_item("Proxy/usage");
if(proxy_use)
{
 foreach port (ports)
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
  command = string("GET gopher://", get_host_name(),":1234 HTTP/1.0\r\n\r\n");
  send(socket:soc, data:command);
  buffer = recv_line(socket:soc, length:4096);
  if((" 200 " >< buffer)||(" 503 "><buffer)||("502 " >< buffer)){ 
  	security_warning(port);
	exit (0);
	}
  close(soc);
  }
 }
}
