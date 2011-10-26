#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10270);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0138");
 name["english"] = "Stacheldraht Detect";
 name["francais"] = "Detection de Stacheldraht";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host appears to be running
Stacheldraht, which is
a trojan that can be used to control
your system or make it attack another
network.

It is very likely that this host
has been compromised

Solution : Restore your system from backups,
	   contact CERT and your local
	   authorities

Risk factor : Critical";



 desc["francais"] = "
Le systeme distant semble faire tourner
Stacheldraht qui peut etre
utilisé pour prendre le controle de celui-ci
ou pour attaquer un autre réseau.

Il est très probable que ce systeme a été
compromis

Solution : reinstallez votre système à partir
	   des sauvegardes, et contactez le CERT
	   et les autorités locales
	   
Facteur de risque : Critique";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detects the presence of Stacheldraht";
 summary["francais"] = "Detecte la présence de Stacheldraht";
 
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


include('global_settings.inc');
if ( islocalhost() ) exit(0);
if ( ! thorough_tests ) exit(0);

src = this_host();
ip = forge_ip_packet(	ip_v : 4,	ip_hl : 5,
			ip_tos : 0,	ip_id : 0x1234,
			ip_len : 20,	ip_off : 0,
			ip_p : IPPROTO_ICMP,
			ip_src : src,	ip_ttl : 0x40);
			
icmp = forge_icmp_packet(ip:ip, icmp_type:0, icmp_code : 0,
			 icmp_seq : 1, icmp_id : 668, 
			 data : "gesundheit!");
			 
filter = string("icmp and src host ", 
		get_host_ip(), 
		" and dst host ", 
		this_host());
		 
r = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter);
if(r)
{
 type = get_icmp_element(icmp:r, element:"icmp_id");
 if(type == 669)security_hole(port:0, protocol:"icmp");
}
