#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10390);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2000-0138");
 
 name["english"] = "mstream agent Detect";
 name["francais"] = "Detection d'un agent mstream";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host appears to be running
a mstream agent, which is a trojan that can be 
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
un agent mstream, qui peut etre utilisé pour prendre 
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
 
 summary["english"] = "Detects the presence of a mstream agent";
 summary["francais"] = "Detecte la présence d'un agent mstream";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}


include('global_settings.inc');
if ( islocalhost() ) exit(0);
if (!  thorough_tests ) exit(0);


function detect(dport, sport)
{  
command = string("ping\n");
ip  = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
		      ip_id:9, ip_tos:0, ip_p : IPPROTO_UDP,
		      ip_len : 20, ip_src : this_host(),
		     ip_ttl : 255);

len = 8 + strlen(command);
udp = forge_udp_packet( ip:ip, 
			uh_sport:65535,
			uh_dport:dport,
			uh_ulen : len, 
			data:command);

filter = string("udp and src host ", get_host_ip(), " and dst port ", sport, " and dst host ", this_host());

r = send_packet(udp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:3);
if(!isnull(r))	{
	dstport = get_udp_element(udp:r, element:"uh_dport");
	if(dstport == sport)return(1);
	else return(0);
    }
else return(0);
}



if(detect(sport:6838, dport:10498))security_hole(10498);
  else if(detect(sport:9325, dport:7983))security_hole(7983);




