#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11109);
 script_cve_id("CVE-2002-1435");
 script_bugtraq_id(5552);
 script_version ("$Revision: 1.14 $");

 name["english"] = "Achievo code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using Achievo.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to Achievo 8.2 or newer
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Achievo";
 
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

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);



tmp = cgi_dirs();
dir = NULL;
foreach d (tmp)
{
 if(isnull(dir))dir = make_list(d, string(d, "/achievo"));
 else dir = make_list(dir, d, string(d, "/achievo"));
}


for(i = 0; dir[i] ; i = i +  1)
 {
 req = http_get(item:string(dir[i], "//atk/javascript/class.atkdateattribute.js.php?config_atkroot=http://xxxxxxxxxx/"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if("http://xxxxxxxxxx/atk/" >< r)
  {
 	security_hole(port);
	exit(0);
  }
}
