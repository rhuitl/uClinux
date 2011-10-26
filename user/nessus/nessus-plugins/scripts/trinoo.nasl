#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10288);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0138");
 
 name["english"] = "Trin00 Detect";
 name["francais"] = "Detection de Trin00";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host appears to be running
Trin00, which is a trojan that can be 
used to control your system or make it 
attack another network (this is 
actually called a distributed denial
of service attack tool)

It is very likely that this host
has been compromised

Solution : Restore your system from backups,
	   contact CERT and your local
	   authorities

Risk factor : Critical";



 desc["francais"] = "
Le systeme distant semble faire tourner
trin00 qui peut etre utilisé pour prendre 
le controle de celui-ci ou pour attaquer un 
autre réseau (outil de déni de service 
distribué)

Il est très probable que ce systeme a été
compromis

Solution : reinstallez votre système à partir
	   des sauvegardes, et contactez le CERT
	   et les autorités locales
	   
Facteur de risque : Critique";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detects the presence of trin00";
 summary["francais"] = "Detecte la présence de trin00";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if ( islocalhost() ) exit(0);
if ( ! thorough_tests ) exit(0);

command = string("png l44adsl");
pong = string("PONG");

ip  = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_UDP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);
		   
length = 8 + strlen(command);		     
udpip = forge_udp_packet(ip : ip,
		         uh_sport : 1024,    
                         uh_dport : 27444,
			 uh_ulen : length,
			 data : command);
			 
			
trg = get_host_ip();
me  = this_host();
pf = string("udp and src host ", trg, " and dst host ", me, " and dst port 31335");
rep = send_packet(udpip, pcap_filter:pf, pcap_active:TRUE);			 	
if(rep)
{
  dstport = get_udp_element(udp:rep, element:"uh_dport");
  if(dstport == 31335)
  { 
   security_hole(port:27444, protocol:"udp");
  }
}
 



