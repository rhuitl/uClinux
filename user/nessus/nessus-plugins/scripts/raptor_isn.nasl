#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11057);
 script_bugtraq_id(5387, 8652);
 script_cve_id("CVE-2002-1463");
 script_version("$Revision: 1.16 $");
 name["english"] = "Weak Initial Sequence Number";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host seems to generate Initial Sequence Numbers (ISN) in a weak 
manner which seems to solely depend on the source and dest port of the TCP 
packets.

An attacker may exploit this flaw to establish spoofed connections to the 
remote host.

The Raptor Firewall and Novell Netware are known to be vulnerable to this 
flaw, although other network devices may be vulnerable as well.


Solution : 

If you are using a Raptor Firewall, see
 http://www.symantec.com/techsupp/bulletin/archive/firewall/082002firewall.html

Otherwise, contact your vendor for a patch.

Reference : http://online.securityfocus.com/archive/1/285729

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "checks for ISN";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Firewalls";
 script_family(english:family["english"]);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

include('global_settings.inc');
if ( ! thorough_tests ) exit(0);
if(islocalhost())exit(0);

 port = get_host_open_port();
 if(!port)exit(0);

  ip1 = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :rand(),
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_TCP,
        ip_src  :this_host()
        );


  ip2 = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :rand(),
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_TCP,
        ip_src  :this_host()
        );
	
  s1 = rand();
  s2 = rand();	
  tcp1 = forge_tcp_packet(ip:ip1,
                               th_sport: 1500,
                               th_dport: port,
                               th_flags:TH_SYN,
                               th_seq: s1,
                               th_ack: 0,
                               th_x2: 0,
                               th_off: 5,
                               th_win: 8192,
                               th_urp: 0);
			       
			       
 tcp2 = forge_tcp_packet(ip:ip1,
                               th_sport: 1500,
                               th_dport: port,
                               th_flags:TH_SYN,
                               th_seq: s2,
                               th_ack: 0,
                               th_x2: 0,
                               th_off: 5,
                               th_win: 0,
                               th_urp: 0);			       
s1 = s1 + 1;
s2 = s2 + 1;

filter = string("tcp and src " , get_host_ip() , " and dst port ", 1500);
r1 = send_packet(tcp1, pcap_active:TRUE, pcap_filter:filter);

if(r1)
{
  # Got a reply - extract the ISN
  isn1 = get_tcp_element(tcp:r1, element:"th_seq");
  ack1  = get_tcp_element(tcp:r1, element:"th_ack");
  if(!(ack1 == s1))exit(0);
  if(!isn1)exit(0); # port closed
  rst1 = forge_tcp_packet(ip:ip1,
  				th_sport:1500,
				th_dport: port,
				th_flags: TH_RST,
				th_seq: ack1,
				th_ack:0,
				th_x2: 0,
				th_off: 5,
				th_win: 0,
				th_urp: 0);
  send_packet(rst1, pcap_active:FALSE);			
  r2 = send_packet(tcp2, pcap_active:TRUE, pcap_filter:filter);
  if(r2)
  {
   # Send the second request
   isn2 = get_tcp_element(tcp:r2, element:"th_seq");
   ack2 = get_tcp_element(tcp:r2, element:"th_ack");
   if(!(ack2 == s2))exit(0);
   if(!isn2)exit(0); # port closed
  
   if(isn1 == isn2)security_hole(0);
  }
}

