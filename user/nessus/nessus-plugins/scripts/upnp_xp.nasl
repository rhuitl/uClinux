#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10829);
 script_bugtraq_id(3723);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2001-0876");
 name["english"] = "scan for UPNP hosts";
 script_name(english:name["english"]);

 desc["english"] = "
Microsoft Universal Plug n Play is running on this machine.  This service is dangerous for many
different reasons.  


Solution: To disable UPNP, see http://grc.com/UnPnP/UnPnP.htm
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "UPNP scan";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2001 by John Lampe");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports(5000);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

include('global_settings.inc');

if( ! thorough_tests ) exit(0);
if(islocalhost())exit(0);
#script based on eeye advisory Multiple Remote Windows XP/ME/98 Vulnerabilities

  myaddr = this_host();
  dstaddr = get_host_ip();
  returnport = 80;

  mystring = string("NOTIFY * HTTP/1.1\r\n");
  mystring = mystring + string("HOST: ", "239.255.255.250" , ":1900\r\n");
  mystring = mystring + string("CACHE-CONTROL: max-age=10\r\n");
  mystring = mystring + string("LOCATION: http://" , myaddr, ":" , returnport , "/foo.xms\r\n");
  mystring = mystring + string("NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n");
  mystring = mystring + string("NTS: ssdp:alive\r\n");
  mystring = mystring + string("SERVER: NESSUS/2001 UPnP/1.0 product/1.1\r\n");
  mystring = mystring + string("USN: uuid:NESSUS\r\n\r\n");
  len = strlen(mystring);

  ippkt = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31337,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_UDP,
        ip_src  :myaddr
        );


  udppacket = forge_udp_packet(
        ip      :ippkt,
        uh_sport:1900,
        uh_dport:1900,
        uh_ulen :8 + len,
        data    :mystring
        );

  for(i=0;i<3;i++)
  {
  rpkt = send_packet(udppacket, pcap_active:FALSE);

  ippkt2 = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31338,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_TCP,
        ip_src  :myaddr
        );

  tcppacket = forge_tcp_packet(ip:ippkt2,
                               th_sport: 999,
                               th_dport: 1900,
                               th_flags:TH_RST,
                               th_seq: 3984,
                               th_ack: 0,
                               th_x2: 0,
                               th_off: 0,
                               th_win: 8192,
                               th_urp: 0);

  filter = string("tcp and src " , dstaddr , " and dst port ", returnport);
  rpkt2 = send_packet(tcppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
  if(rpkt2)
  {
  flags = get_tcp_element(tcp:rpkt2, element:"th_flags");

  if (flags & TH_SYN) {
       security_hole(port:1900,protocol:"udp");
  }
  exit(0);     
  }
  }

