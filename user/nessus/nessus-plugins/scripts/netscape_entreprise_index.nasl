#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10691);
 script_bugtraq_id(2285);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2001-0250");
 
 name["english"] = "Netscape Enterprise INDEX request problem";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server gives a file listing when it is issued the
command :
		INDEX /	HTTP/1.1

An attacker may use this flaw to discover the internal
structure of your website, or to discover supposedly hidden
files.

Solution : disable web publishing or INDEX requests 
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "INDEX / HTTP/1.1";
 summary["francais"] = "INDEX / HTTP/1.1";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iplanet");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  req = string("INDEX / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n");
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  close(soc);
  if("Content-Type: text/plain" >< r)
  {
   if("null" >< r)
  {
   if(egrep(pattern:"directory|unknown", string:r))security_warning(port);
  }
 }
}
