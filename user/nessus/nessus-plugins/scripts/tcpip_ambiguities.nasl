#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
#
# Ref:
# To: bugtraq@securityfocus.com
# From: security@sco.com
# Date: Mon, 5 May 2003 11:01:07 -0700
# Subject: Security Update: [CSSA-2003-019.0] OpenLinux: tcp SYN with FIN 
#          packets are not discarded
#

if(description)
{
 script_id(11618);
 script_bugtraq_id(7487);
 script_version ("$Revision: 1.9 $");
 name["english"] = "Remote host replies to SYN+FIN";
 
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It may be possible to bypass firewall rules

Description :

The remote host does not discard TCP SYN packets which have
the FIN flag set.

Depending on the kind of firewall you are using, an attacker
may use this flaw to bypass its rules.

See also :

http://archives.neohapsis.com/archives/bugtraq/2002-10/0266.html
http://www.kb.cert.org/vuls/id/464113
	   
Solution :

Contact your vendor for a patch

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a SYN+FIN packet and expects a SYN+ACK";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Firewalls";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#

# do not test this bug locally
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

if(islocalhost())exit(0);

port = get_host_open_port();
if(!port)exit(0);

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_TCP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

tcp = forge_tcp_packet(ip:ip, th_sport:10004, th_dport:port, 
		       th_win:4096,th_seq:rand(), th_ack:0,
		       th_off:5, th_flags:TH_SYN|TH_FIN, th_x2:0,th_urp:0);
		       
filter = string("tcp and src host ", get_host_ip(), " and dst host ",
this_host(), " and src port ", port, " and dst port ", 10004, " and tcp[13]=18");

for(i=0;i<5;i++)
{
 r = send_packet(tcp, pcap_active:TRUE, pcap_timeout:1, pcap_filter:filter);
 if(r)
 {
  # We specified a pcap filter which only returns SYN|ACK....
  security_note(0);
  exit(0);
 }
}
