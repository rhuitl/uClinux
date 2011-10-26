#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10178);
 script_bugtraq_id(712);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0058");
 name["english"] = "php.cgi buffer overrun";
 name["francais"] = "php.cgi buffer overrun";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "There is a buffer overrun in
the 'php.cgi' CGI program, which will allow anyone to
execute arbitrary commands with the same privileges as the
web server (root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Il y a un dépassement de buffer
dans le CGI 'php.cgi', qui permet à n'importe qui d'executer
des commandes arbitraires avec les memes privilèges que le 
serveur web (root ou nobody).

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the /cgi-bin/php.cgi buffer overrun";
 summary["francais"] = "Vérifie le dépassement de buffer de /cgi-bin/php.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"php.cgi", port:port);
if(res)
{
 c = string("php.cgi?", crap(32000));
 p2 = is_cgi_installed_ka(item:c, port:port);
 if(p2 == 0)
 {
  security_hole(port);
 }
}
