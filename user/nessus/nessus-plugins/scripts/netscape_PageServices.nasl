#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10153);
 script_bugtraq_id(7621);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0269");
 name["english"] = "Netscape Server ?PageServices bug";
 
 script_name(english:name["english"]);
 
 desc["english"] = "Requesting an URL with '?PageServices' appended to
it makes some Netscape servers dump the listing of the page 
directory, thus revealing potentially sensitive files to an attacker.

Solution : Upgrade your Netscape server or turn off indexing

Risk factor : Medium
";
 script_description(english:desc["english"], francais:desc["francais"]); 
 summary["english"] = "Make a request like http://www.example.com/?PageServices";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iplanet");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(get_port_state(port))
{
  seek = "<title>index of /</title>";
  data = http_get_cache(item:"/", port:port);
  data_low = tolower(data);
  if(seek >< data_low)exit(0);
  
  soc = http_open_socket(port);
  if ( ! soc ) exit(0);
  buffer = http_get(item:"/?PageServices", port:port);
  send(socket:soc, data:buffer);
  data = http_recv(socket:soc);
  http_close_socket(soc);
  data_low = tolower(data);
  
  if(seek >< data_low) security_warning(port);
}
