#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16185);
 script_bugtraq_id(12292, 12286);
 script_version ("$Revision: 1.5 $");
 name["english"] = "Gallery Multiple Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Gallery web-based photo album.

There are various flaws in the remote version of this software which
may allow an attacker to perform a cross site scripting attack using
the remote host, or to exploit an information disclosure flaw to gain
more knowledge about the remote system.

Solution : None at this time
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of login.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

function check(url)
{
req = http_get(item:string(url, '/login.php?username="<script>foo</script>'),
 		port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if ( r == NULL ) exit(0);
if('<input type=text name="username" value=""<script>foo</script>"' >< r )
 	{
 	security_warning(port);
	exit(0);
	}
}

foreach dir (cgi_dirs())
 check(url:dir);
