#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:  http://www.securitytracker.com/alerts/2003/Apr/1006556.html

if(description)
{
 script_id(11601);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MailMaxWeb Path Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running MailMaxWeb, a web-mail
interface.

There is a flaw in this version which makes it disclose
the physical path to its remote installation.

An attacker may use this flaw to gain further knowledge
about the remote host.

Solution : None at this time.
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MailMaxWeb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


foreach d (cgi_dirs())
{
 req = http_get(item:d+"/", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 if("Set-Cookie: IX=" >< res)
 {
  if(egrep(pattern:".*value=.[A-Z]:\\", string:res))
  	{
	security_note(port);
	exit(0);
	}
 }
}
