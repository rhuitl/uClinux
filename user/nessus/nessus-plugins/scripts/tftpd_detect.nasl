#
# (C) Tenable Network Security
#
# Revised 19/02/05 by Martin O'Neal of Corsaire to make the detection more positive, include the 
#                  correct CVE and to update the knowledgebase appropriately 
#

if(description)
{
 script_id(11819);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-1999-0616");
 
 name["english"] = "a tftpd server is running";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A TFTPD server is listening on the remote port.

Description :

The remote host is running a TFTPD (Trivial File Transfer Protocol).
TFTPD is often used by routers and diskless hosts to retrieve their
configuration. It is also used by worms to propagage.

Solution : 

If you do not use this service, you should disable it.

Risk factor :

None";

 script_description(english:desc["english"]);
 
 summary["english"] = "tftpd Server detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 script_dependencies('external_svc_ident.nasl');
 exit(0);
}

#
# The script code starts here
#
include('misc_func.inc');

if(islocalhost())exit(0);
req = raw_string(0x00, 0x01) + "nessus" + rand() + raw_string(0x00) + "netascii" + raw_string(0x00);

sport = rand() % 64512 + 1024;		     

ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0, ip_len:20, ip_id:rand(), ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
		     ip_src:this_host());
myudp = forge_udp_packet(ip:ip, uh_sport: sport, uh_dport:69, uh_ulen: 8 + strlen(req), data:req);

# Some backdoors never return "file not found"
# filter = 'udp and dst port 4315 and src host ' + get_host_ip() + ' and udp[9:1]=0x05';
filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

for ( i = 0 ; i < 3 ; i ++ )
{
 rep = send_packet(myudp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);	     
 if ( rep ) break;
}

if(rep)
{
 data = get_udp_element(udp:rep, element:"data");
 if(data[0] == '\0' && (data[1] == '\x03' || data[1] == '\x05'))
 {
  security_note(port:69, proto:"udp");
  register_service(port: 69, ipproto: 'udp', proto: 'tftp');
 }
}
