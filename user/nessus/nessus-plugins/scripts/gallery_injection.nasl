#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#
# This check covers CVE-2001-1234, but a similar flaw (with a different
# CVE) was found later on.
#
# Ref: http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=50


if(description)
{
 script_id(11115);
 script_bugtraq_id(3397);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-1234");
 name["english"] = "gallery code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using Gallery.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Reference : http://online.securityfocus.com/bid/3397

Solution : Upgrade to Gallery 1.3.1 or newer
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of includes/needinit.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
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


if( ! get_port_state(port))exit(0);
if( ! can_host_php(port:port) ) exit(0);
if(http_is_dead(port:port))exit(0);

function check(url)
{
req = http_get(item:string(url, "/errors/needinit.php?GALLERY_BASEDIR=http://xxxxxxxx/"),
 		port:port);
r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);
 if("http://xxxxxxxx/errors/configure_instructions" >< r)
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
