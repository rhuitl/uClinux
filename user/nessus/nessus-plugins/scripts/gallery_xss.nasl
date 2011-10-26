#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(11810);
 script_bugtraq_id(8288);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0614");
 name["english"] = "gallery xss";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Gallery web-based photo album.

There is a flaw in this version which makes it vulnerable to
a cross site scripting attack which may allow an attacker
to steal the cookies from the legitimate users of this system.

Solution : Upgrade to Gallery 1.3.4p1 or newer
Risk factor : Low";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of search.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
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
req = http_get(item:string(url, "/search.php?searchstring=<script>foo</script>"),
 		port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if ( r == NULL ) exit(0);
 if("<script>foo</script>" >< r)
 	{
 	security_warning(port);
	exit(0);
	}
 
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
