# Written by Michel Arboi <arboi@alussinan.org>
# Released under the GNU Public Licence v2
#
# References:
# RFC 792 Internet Control Message Protocol
# RFC 791 Internet Protocol
#
#

if(description)
{
 script_id(12264);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "Record route";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin sends packets with the 'Record Route' option. 
It is a complement to traceroute.

Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Ping target with Record Route option";
 script_summary(english:summary["english"]);

# script_category(ACT_GATHER_INFO);
 # See bugtraq ID # 10653
 script_category(ACT_DESTRUCTIVE_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 
 exit(0);
}

#
include("misc_func.inc");
include("dump.inc");
if (islocalhost()) exit(0); # Don't test the loopback interface

srcaddr = this_host();
dstaddr = get_host_ip();
n = 3;	# Number of tries

function report(packet, proto)
{
 local_var	rep, ihl, p, i, j, route;

 if ( ! packet ) return 0;

 rep = strcat('Here is the route recorded between ', srcaddr, 
	' and ', dstaddr, ' :\n');

 ihl = (ord(packet[0]) & 0xF) * 4;
 ##display("IHL=", ihl, "\n");
 # No need to associate this piece of information with a specific port
 ##dump(ddata: packet, dtitle: "packet");
 p = ord(packet[22]) + 20;
 if (p > ihl) p = ihl;
 for (i = 24; i < p; i += 4)
 {
  for (j = -1; j < 3; j ++)
   route = strcat(route, ord(packet[i+j]), '.');
  route = strcat(route, '\n');
 }
 if ( strlen(route) > 4 )
 security_note(port: 0, protocol: proto, data: rep + route);
}

# Currently, insert_ip_options() is buggy
rr = raw_string(	7,	# RR
			3+36,	# Length
			4,	# Pointer
			0)	# Padding
 + crap(length: 36, data: raw_string(0));


# We cannot use icmp_seq to identifies the datagrams because 
# forge_icmp_packet() is buggy. So we use the data instead

filter = strcat("icmp and icmp[0]=0 and src ", dstaddr, " and dst ", srcaddr);
seq = 0;

d = rand_str(length: 8);
for (i = 0; i < 8; i ++)
  filter = strcat(filter, " and icmp[", i+8, "]=", ord(d[i]));

ip = forge_ip_packet(ip_hl: 15, ip_v: 4, ip_tos: 0, ip_id: rand() % 65536,
	ip_off: 0, ip_ttl : 0x40, ip_p: IPPROTO_ICMP, ip_src : srcaddr, 
	data: rr, ip_len: 38+36);
icmp = forge_icmp_packet(ip: ip, icmp_type:8, icmp_code:0, icmp_seq: seq, 
	icmp_id: rand() % 65536, data: d);
r = NULL;
for (i = 0; i < n && ! r; i ++)
  r = send_packet(icmp, pcap_active: TRUE, pcap_filter: filter);
if (i < n) report(packet: r, proto: "icmp");
