#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: http://archives.neohapsis.com/archives/bugtraq/2003-04/0027.html

if(description)
{
 script_id(11605);
 script_bugtraq_id(7361);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "IkonBoard arbitrary command execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running IkonBoard, a forum management CGI.

There is a flaw in this version which allows an attacker to 
execute arbitrary commands on this host.


Solution : Upgrade to the latest version of this CGI.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Ikonboard.cgi";
 
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
 req = http_get(item:d+"/ikonboard.cgi", port:port);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, string("\r\nCookie: lang=%2E%00%22\r\n\r\n"), idx);
 res = http_keepalive_send_recv(port:port, data:req);
 
  
 if ( res == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res))
 {
  if(egrep(pattern:".*EOF.*\(eval 6\) line 1", string:res))
  	{
	security_hole(port);
	exit(0);
	}
 }
}
