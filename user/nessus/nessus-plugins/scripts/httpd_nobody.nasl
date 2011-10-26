#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10484);
 script_version ("$Revision: 1.10 $");

 name["english"] = "Read any file thanks to ~nobody/";
 name["francais"] = "Read any file thanks to ~nobody/";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to access arbitrary files on the remote
web server by appending ~nobody/ in front of their
name (as in ~nobody/etc/passwd).

This problem is due to a misconfiguration in your Apache
server that sets UserDir to ./.

Solution : Set UserDir to public_html/ or something else
Risk factor : High";


 desc["francais"] = "
Il est possible de lire des fichiers arbitraires sur l'hote
distant en rajoutant ~nobody devant leur nom (comme dans
~nobody/etc/passwd).

Ce problème est vraisemblablement du à une mauvaise configuration
d'Apache qui met UserDir à './' au lieu d'autre chose.

Solution : changez la valeur de UserDir dans le fichier de configuration
d'Apache en quelque chose d'autre (public_html par exemple)
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /~nobody/etc/passwd";
 summary["francais"] = "Vérifie la présence de /~nobody/etc/passwd";
 
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
  req = http_get(item:"/~nobody/etc/passwd", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( ! res ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:res))security_hole(port);
}

