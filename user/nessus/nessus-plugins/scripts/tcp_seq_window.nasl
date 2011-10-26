#
# (C) Tenable Network Security
#
if(description)
{
  script_id(12213);
  script_bugtraq_id(10183);
  script_cve_id("CVE-2004-0230");
  if ( defined_func("script_xref")) script_xref(name:"OSVDB", value:"4030");
  if ( defined_func("script_xref")) script_xref(name:"IAVA", value:"2004-A-0007");
  
  script_version("$Revision: 1.20 $");

  script_name(english:"TCP sequence number approximation");
  script_description(english:"
The remote host might be vulnerable to a sequence number approximation
bug, which may allow an attacker to send spoofed RST packets to the remote
host and close established connections.

This may cause problems for some dedicated services (BGP, a VPN over
TCP, etc...).

Solution : See http://www.securityfocus.com/bid/10183/solution/
Risk factor : Medium");
  script_summary(english:"Check for TCP approximations on the remote host");
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is (C) 2004 Tenable Network Security");
  script_dependencies("smb_nativelanman.nasl");
  script_require_ports(139,445);

  exit(0);
}





include('global_settings.inc');

#
# The script code starts here

# if you want to test from CLI, then just supply the two values below
debug=0;

# I think it's worth noting the methodology of this check, as it will likely
# flag on most OSes
# 1) create a valid socket from the Nessus scanner to the host on some open port
# 2) hold the socket from (1) open, and spoof a RST with the sequence number incremented by
#    512 from the valid tuple defining the socket (i.e. srchost, dsthost, srcport, dstport)
# 3) send a character to the socket created in (1)
# 4) check for a RST from the host
# if we get a RST in (4), then that indicates that the system accepted and processed
# our spoofed RST from (2)...and, that is the very nature of this bug.

#if ( report_paranoia < 2 ) exit(0);
if (!defined_func ("get_source_port")) exit(0);
if ( islocalhost() ) exit(0);

# get an open port and name it port
os = get_kb_item ("Host/OS/smb") ;
if ( os && "Windows" >< os)
{
 port = int(get_kb_item("SMB/transport"));
}
else
{
 port = get_host_open_port();
 if ( (!port) && (!debug) ) exit(0);
}

soc = open_sock_tcp (port);
if (!soc) exit(0);
sport = get_source_port (soc);
req = string("G");

#get an ack number from the host 

dstaddr=get_host_ip();
srcaddr=this_host();


filter = string("tcp and src ", dstaddr, " and dst ", srcaddr, " and dst port ", sport, " and src port ", port );

if ( defined_func("send_capture") )
 result = send_capture(socket:soc, data:req, pcap_filter:filter);
else 
{
 send(socket:soc, data:req);
 result = pcap_next(pcap_filter:filter);
}

if (result)  {
  tcp_seq = get_tcp_element(tcp:result, element:"th_ack");
  flags = get_tcp_element(tcp:result, element:"th_flags");
} else {
  if (debug) display("no result packet to pull sequence number from\n");
  exit(0);
}

# some protocols will take a single character and then close the connection...
# in these instances, we'll just exit the check...remember, only long-lived connections
# are truly at risk 
if  ( (! tcp_seq) || (flags & TH_FIN) || (flags & TH_RST) ) {
    if (debug) display("The remote host has closed the connection prior to our RST packet\n");
    exit(0); 
}

# now.....SPOOF a RST after incrementing our Sequence num by 512
 

ip2 = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);

newsequence = tcp_seq + 512;

tcpip = forge_tcp_packet(    ip       : ip2,
                             th_sport : sport,
                             th_dport : port,
                             th_flags : TH_RST,
                             th_seq   : newsequence,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);


result = send_packet(tcpip,pcap_active:FALSE);
sleep(1);

result = NULL;
for ( i = 0; i < 3 && ! result; i ++ )
{
 send_packet(tcpip,pcap_active:FALSE);
 if ( defined_func("send_capture") )
  result = send_capture(socket:soc, data:req, pcap_filter:filter, timeout:5);
 else 
  {
  send(socket:soc, data:req);
  result = pcap_next(pcap_filter:filter, timeout:5);
  }
}

if (result) {
    flags = get_tcp_element(tcp:result, element:"th_flags");
    if (flags & TH_RST) {
        if (debug) display("The remote host RSTed our packet...it's vulnerable\n");
        if( report_paranoia > 1 ) security_warning(0);
        set_kb_item (name:"TCP/seq_window_flaw", value:TRUE);
        exit(0);
    }
} else {
    if ( report_paranoia > 1 )
     {
     # our socket is dead
     if (debug) display("no response on soc...we should have gotten RST ACK or FIN\n");
     security_warning(0);
     }
    set_kb_item (name:"TCP/seq_window_flaw", value:TRUE);
    exit(0);
 }

# make sure that we don't 'accidentally' FIN our valid socket...this last send call makes sure
# that we hold the socket open till the end of the check....

send(socket:soc, data:req);
close(soc);


