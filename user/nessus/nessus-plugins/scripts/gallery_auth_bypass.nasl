#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(12278);
 script_cve_id("CVE-2004-0522");
 script_bugtraq_id(10451);
 script_version ("$Revision: 1.6 $");
 name["english"] = "gallery authentication bypass";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Gallery web-based photo album.

There is a flaw in this version which may allow an attacker to bypass
the authentication mechanism of this software by making requests including
the options GALLERY_EMBEDDED_INSIDE and GALLERY_EMBEDDED_INSIDE_TYPE.

Solution : Upgrade to Gallery 1.4.3p2 or newer
Risk factor : Low";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a bug in gallery";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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


function check(url)
{
req = http_get(item:string(url, "/index.php"),
 		port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if ( r == NULL ) exit(0);
if(egrep(pattern:'<span class="admin"><a id="popuplink_1".*\\[login\\]', string:r)
)
 	{
	 req = http_get(item:string(url, "/index.php?GALLERY_EMBEDDED_INSIDE=y"),
 		port:port);
	r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
	if ( r == NULL ) exit(0);
	if(egrep(pattern:'<span class="admin"><a id="popuplink_1".*\\[login\\]', string:r) == 0 )
 		security_warning(port);
	exit(0);
	}
 
}

check(url:"");
foreach dir (cgi_dirs())
{
 check(url:dir);
}
