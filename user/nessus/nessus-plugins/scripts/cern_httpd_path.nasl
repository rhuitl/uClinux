#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10037);
 script_bugtraq_id(936);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0079");
 name["english"] = "CERN httpd problem";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to
get the physical location of a
virtual web directory of this host by 
issuing the command :

	GET /cgi-bin/ls HTTP/1.0
	
Usually, the less the attacker knows about your
system, the better it feels, so you should
correct this problem.

Solution : use Apache (www.apache.org) since
           CERN httpd is no longer maintained

Bugtraq ID : 936
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to find the location of the remote web root";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/cern");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
  d = string(dir, "/ls");
  req = http_get(item:d, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  r = tolower(r);
  if(" neither '/" >< r){
  	security_warning(port);
	exit(0);
	}
}

