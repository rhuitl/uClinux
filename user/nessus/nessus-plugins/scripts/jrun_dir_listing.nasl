#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10604);
 script_bugtraq_id(1830);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-1050");

 name["english"] = "Allaire JRun Directory Listing";
 name["francais"] = "Allaire JRun Directory Listing";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Requesting a URL with '/./' prepended to it
makes the remote Allaire Server display the content of 
a remote directory, instead of its index.html file.

An attacker may use this flaw to download 'hidden' files on 
your server.

Solution : upgrade to JRun 3.0sp2
Risk factor : Medium";

 desc["francais"] = "
Demander une URL avec un '/./' au début force un serveur
Allaire à afficher le contenu du répertoire demandé, au lieu
du traditionel index.html.

Un pirate peut utiliser ce problème pour télécharger les fichiers
'cachés' de votre serveur.

Solution : mettez à jour JRun 3.0sp2
Facteur de risque : Moyen";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Make a request like http://www.example.com/./WEB-INF";
 summary["francais"] = "Fait une requête du type http://www.example.com/./WEB-INF";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8000);
if(get_port_state(port))
{
  req = http_get(item:"/./WEB-INF/", port:port);
  r =   http_keepalive_send_recv(port:port, data:req);
  if(ereg(pattern:"^HTTP.* 200 ", string:r)  )
  {
   if("Index of /./WEB-INF/" >< r)security_warning(port);
  }
}
