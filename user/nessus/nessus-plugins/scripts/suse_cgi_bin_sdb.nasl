#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10503);
 script_bugtraq_id(1658);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0868");

 name["english"] = "Reading CGI script sources using /cgi-bin-sdb";
 name["francais"] = "Lecture des sources des CGIs grace à /cgi-bin-sdb";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The directory /cgi-bin-sdb is an Alias of
/cgi-bin - most SuSE systems are configured that
way.

This setting allows an attacker to obtain the source
code of the installed CGI scripts on this host. This is 
dangerous as it gives an attacker valuable information
about the setup of this host, or perhaps usernames and
passwords if they are hardcoded into the CGI scripts.

Solution : In httpd.conf, change the directive: 
Alias /cgi-bin-sdb/ /usr/local/httpd/cgi-bin/
to
ScriptAlias /cgi-bin-sdb/ /usr/local/httpd/cgi-bin/
Risk factor : High";



 desc["francais"] = "
Le dossier /cgi-bin/sdb est un Alias vers
/cgi-bin - ce qui est la configuration de la 
plupart des SuSE.

Ce paramètre permet a un pirate d'obtenir
le code source des CGIs installés sur ce
serveur. C'est dangereux dans le sens où 
cela lui donne plus d'informations sur
l'organisation de cette machine, ou meme
d'obtenir un accès plus privilégié sur
ce serveur si le CGI contient des
noms d'utilisateurs ou mots de passe codés
en dur.

Solution : Changez, dans httpd.conf, la directive
Alias /cgi-bin-sdb/ /usr/local/httpd/cgi-bin/
en
ScriptAlias /cgi-bin-sdb/ /usr/local/httpd/cgi-bin/
Facteur de risque : Sérieux";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin-sdb/";
 summary["francais"] = "Vérifie la présence de /cgi-bin/sdb/";
 
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
  # First try : attempt to get printenv
  req = string("/cgi-bin-sdb/printenv");
  req = http_get(item:req, port:port);
  r   = http_keepalive_send_recv(port:port, data:req);
  if ( ! r ) exit(0);
  if("/usr/bin/perl" >< r)
  {
  	security_hole(port);
	exit(0);
  }
 
  req = string("/cgi-bin-sdb/sdbsearch.cgi");
  req = http_get(item:req, port:port);
  r   = http_keepalive_send_recv(port:port, data:req);
  if("HTTP/1.1 403 " >< r){
  	#
	# Attempt to obtain something else in the same
	# directory
	#
	req = http_get(item:"/cgi-bin-sdb/nessus", port:port);
  	r   = http_keepalive_send_recv(port:port, data:req);
	if("HTTP/1.1 403 " >< r)
	  exit(0);
	else
  	 security_hole(port);
	exit(0);
	}
}
