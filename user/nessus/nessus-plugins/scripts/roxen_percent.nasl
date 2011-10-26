#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10479);
 script_bugtraq_id(1510);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0671");
 name["english"] = "Roxen Server /%00/ bug";
 name["francais"] = "Roxen Server /%00/ bug";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Requesting a URL with '/%00/' appended to it
makes some Roxen servers dump the listing of the page 
directory, thus showing potentially sensitive files.

An attacker may also use this flaw to view
the source code of RXML files, Pike scripts
or CGIs.

Under some circumstances, 
information protected by .htaccess files might
be revealed.

Risk factor : High
Solution : upgrade to the latest version of Roxen";

 desc["francais"] = "Demander une URL finissant par '/%00/' 
force certains serveurs Roxen à afficher le contenu du répertoire
de la page, montrant ainsi des fichiers potentiellement sensibles.

Un pirate peut aussi utiliser ce problème pour obtenir
le code source des fichiers RXML, des scripts Pike
et meme des CGIs.

Enfin, les données controlées par un fichier .htaccess
peuvent etre revelées.

Facteur de risque : Elevé.
Solution : Mettez Roxen à jour en sa dernière version";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Make a request like http://www.example.com/%00/";
 summary["francais"] = "Fait une requête du type http://www.example.com/%00/";
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
  buffer = http_get(item:"/%00/", port:port);
  data = http_keepalive_send_recv(port:port, data:buffer);
  seek = "Directory listing of";
  if(seek >< data)
  {
   security_hole(port);
  }
}
