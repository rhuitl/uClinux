#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# From: Karol Wiesek <appelast@bsquad.sm.pl>
# To: bugtraq@securityfocus.com
# Subject: GOnicus System Administrator php injection
# Message-ID: <20030224164419.GA13904@bsquad.sm.pl>


if(description)
{
 script_id(11275);
 script_bugtraq_id(6922);
 # script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.11 $");

 name["english"] = "GOsa code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using GOsa.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to GOsa 1.0.1 or newer
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of remotehtmlview.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
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
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/include/help.php?base=http://xxxxxxxx"),
 		port:port);	
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxxxx/include/common\.inc", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
