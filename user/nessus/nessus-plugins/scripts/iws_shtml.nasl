#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10538);
 script_bugtraq_id(1848);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2000-1077");
 
 name["english"] = "iWS shtml overflow";
 name["francais"] = "Overflow shtml dans iWS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to make the remote iPlanet web server execute
arbitrary code when requesting a too long .shtml file (with a name 
longer than 800 chars and containing computer code).

An attacker may use this flaw to gain a shell on this host

Solution : Disable server side parsing of HTML page (Content Management -> Parse HTML)
Risk factor : High";

 desc["francais"] = "
Il est possible de faire executer du code arbitraire au serveur
iPlanet distant en demandant un fichier trop long dont le nom
fini par .shtml (avec un nom > 800 caractères et contenant du
code machine).

Un pirate peut utiliser ce problème pour obtenir un shell sur
cette machine.

Solution : désactivez l'option de parse HTML (Content Management -> Parse HTML)
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Web server buffer overflow";
 summary["francais"] = "Dépassement de buffer dans un serveur web";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www",80);
 script_require_keys("www/iplanet");
 exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

soc = http_open_socket(port);
if(soc)
{
  banner = get_http_banner(port:port);
  if(egrep(pattern:"^Server:.*Netscape-Enterprise", string:banner))
  {
  soc = http_open_socket(port);
  req1 = http_get(item:"/XXX.shtml", port:port);
  send(socket:soc, data:req1);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(r)
  {
   soc = http_open_socket(port);
   if(soc)
   {
   req2 = http_get(item:string("/", crap(800), ".shtml"), port:port);
   send(socket:soc, data:req2);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   if(!r)security_hole(port);
   }
  }
 }
}




