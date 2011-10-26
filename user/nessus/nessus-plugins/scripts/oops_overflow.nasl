#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Should also cover http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0082.html
#

if(description)
{
 script_id(10578);
 script_bugtraq_id(2099);
 script_cve_id("CVE-2001-0029");
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "Oops buffer overflow";
 name["francais"] = "Dépassement de buffer dans Oops";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote proxy server seems to be ooops 1.4.6 or older.

This proxy is vulnerable to a buffer overflow that
allows an attacker to gain a shell on this host.

*** Note that this check made the remote proxy crash

Solution : Upgrade to the latest version of this software
Risk factor : High";

	
 desc["francais"] = "
Le serveur proxy distant semble etre oops 1.4.6 ou plus
ancien.

Ce proxy est vulnérable à une attaque qui permet à un
pirate d'obtenir un shell sur ce système.

*** Notez que ce test de sécurité a tué le proxy

Solution : Mettez ce proxy à jour en sa dernière version
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Overflows oops";
 summary["francais"] = "Dépassement de buffer dans oops";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/http_proxy", 3128);
 exit(0);
}


include("http_func.inc");

port = get_kb_item("Services/http_proxy");
if(!port) port = 3128;


if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:string("http://", crap(12)), port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if ( ! r ) exit(0);
  close(soc);

  soc = http_open_socket(port);
  if ( ! soc ) exit(0);

  req = http_get(item:string("http://", crap(1200)), port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc); 
  http_close_socket(soc); 

  if(http_is_dead(port:port))security_hole(port);
 }
}
