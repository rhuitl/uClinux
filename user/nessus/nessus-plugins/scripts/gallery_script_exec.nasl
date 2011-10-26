#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(14338);
 script_cve_id("CVE-2004-1466");
 script_bugtraq_id(10968);
 script_version ("$Revision: 1.5 $");
 name["english"] = "Gallery Script Execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Gallery web-based photo album.

There is a flaw in the remote version of this software which may
allow an attacker to execute arbitrary commands on the remote host.

To exploit this flaw, an attacker would require the privileges to
upload files to a remote photo album.

Solution : Upgrade to Gallery 1.4.4-pl2 or newer
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Gallery";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
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
req = http_get(item:string(url, "/index.php"), port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if ( r == NULL ) exit(0);
if ( egrep(pattern:".*Powered by.*Gallery.*v(0\.|1\.([0-3]\.|4\.([0-3][^0-9]|4 |4-pl[01]([^0-9]|$))))", string:r) )
	{
	security_hole(port);
	exit(0);
	}
}

check(url:"");
foreach dir (cgi_dirs())
{
 check(url:dir);
}
