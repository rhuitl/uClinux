#
# (C) Tenable Network Security
#
if(description)
{
  script_id(11858);
# script_cve_id("CVE-MAP-NOMATCH");
  script_version("$Revision: 1.4 $");
  script_name(english:"TTL Anomaly detection");
  script_description(english:"
The remote host, when queried on open ports, replies with differing TTL values.  This could be an 
indicator that a transparent proxy is on the way, or that this host is a forwarding router, 
honeypot, etc...

An attacker may use this information to find critical systems on your network 
Solution: Contact vendor for information on closing up this information leak. 

Risk factor : Low");
  script_summary(english:"Check for TTL anomalies on the remote host");
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is (C) 2003 Tenable Network Security");
  exit(0);
}



#
# The script code starts here

dstaddr=get_host_ip();
srcaddr=this_host();
if(islocalhost())exit(0);

IPH = 20;
IP_LEN = IPH;


openflag = j = 0;

ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))exit(0);


foreach port (keys(ports))
#foreach port (ports)
 {
  #port = int(port - "Ports/tcp/");
  if (get_port_state(port)) {
    # 3 times is a charm...Let's make sure there are no initial anomalies
    receivedpackets = 0;                           #increment this for each packet pcap reads back in
    for (mu=0; mu < 3; mu++) {
      srcport = rand() % 65535;
      ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);


      tcpip = forge_tcp_packet(    ip       : ip,
                             th_sport : srcport,
                             th_dport : port,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);
  
   
      filter = string("(dst port ", srcport, " ) and (src ", dstaddr, " )" );
      result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
      if (result)  {
        myttl = get_ip_element(ip:result, element:"ip_ttl");
        myrray[mu] = myttl;
        receivedpackets++;
        # display(string(myttl, "\n"));                         #remove remove remove
      } 
  
    }   # end mu


    if (receivedpackets == 3) { 
      # if we get differing TTLs for a single port, we've got a live one..
      if ( (myrray[0] != myrray[1]) || (myrray[0] != myrray[2]) ) { 
        security_note(port);
        exit(0);
      } else {
        myttlrray[j] = myttl;
        portnum[j] = port;
      }
      j++;
    }  

  } # end get_port_state(port);

}


# now, let's loop through myttlrray array and see if we have differing values....

if (strlen(myttlrray) > 2)  {
  for (i=1; myttlrray[i]; i++) {
    if (myttlrray[i] != myttlrray[0]) security_note(portnum[i]);
    exit(0);
  }
}


exit(0);

#
# We could do the same thing for UDP, but that may take too long and
# may disable remote services
#


myttlrray = '';


openflag = j = 0;
while (port = scanner_get_port(openflag++)) {
  if (get_udp_port_state(port)) {
    receivedpackets = 0;                           
    for (mu=0; mu < 3; mu++) {
      srcport = rand() % 65535;
      ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_UDP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);


      udpip = forge_udp_packet(    ip       : ip,
                             uh_sport : srcport,
                             uh_dport : port);


      filter = string("udp and (dst port ", srcport, " ) and (src ", dstaddr, " )" );
      result = send_packet(udpip, pcap_active:TRUE, pcap_filter:filter);
      if (result)  {
        myttl = get_ip_element(ip:result, element:"ip_ttl");
        myrray[mu] = myttl;
        receivedpackets++;
      }

    }   # end mu


    if (receivedpackets == 3) {
      # if we get differing TTLs for a single port, we've got a live one..
      if ( (myrray[0] != myrray[1]) || (myrray[0] != myrray[2]) ) {
        security_note(port);
        exit(0);
      } else {
        myttlrray[j] = myttl;
        portnum[j] = port;
      }
      j++;
    }

  } # end get_port_state(port);

}


if (strlen(myttlrray) > 2) {
  for (i=1; myttlrray[i]; i++) {
    if (myttlrray[i] != myttlrray[0]) security_note(portnum[i]);
    exit(0);
  }
}


exit(0);
  




