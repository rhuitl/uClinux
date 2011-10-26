#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
command execution.

Description :

The 'wwwwais' CGI is installed.  This CGI has a well known security
flaw that lets an attacker execute arbitrary commands with the
privileges of the http daemon (usually root or nobody). 

See also : 

http://marc.theaimsgroup.com/?l=bugtraq&m=97984174724339&w=2

Solution : 

Remove the script.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(10597);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-0223");
 script_bugtraq_id(2292);
 

 name["english"] = "wwwwais";
 name["francais"] = "wwwwais";
 script_name(english:name["english"], francais:name["francais"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/wwwwais";
 summary["francais"] = "Vérifie la présence de /cgi-bin/wwwwais";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);



foreach dir (cgi_dirs())
{
 file = string(dir, "/wwwwais?version=123&", crap(4096));
 req = http_get(item:file, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if("memory violation" >< r)
	security_hole(port);
}
