#
# (C) Tenable Network Security
#
# Thanks to Philippe Biondi <biondi@cartel-securite.fr> for his
# help.
#
#
# See the Nessus Scripts License for details
#
# Ref: http://www.cartel-securite.fr/pbiondi/adv/CARTSA-20030314-icmpleak
# Ref: VU#471084 (http://www.kb.cert.org/vuls/id/471084)
#
# Refs:
#  Date: Mon, 9 Jun 2003 08:56:55 +0200 (CEST)
#  From: Philippe Biondi <biondi@cartel-securite.fr>
#  To: vuln-dev@securityfocus.com, <full-disclosure@lists.netsys.com>,
#        <bugtraq@securityfocus.com>
#  Subject: Linux 2.0 remote info leak from too big icmp citation

if(description)
{
 script_id(11704);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2003-0418");

 name["english"] = "icmp leak";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to an 'icmp leak' of
potentially confidential data.  That is, when the 
host generates an ICMP error packet other than 
'destination unreachable', the  error packet is 
supposed to only contain the original message or 
a portion of the original message. 

Due to a bug in the remote TCP/IP stack, these ICMP
error messages will also contain fragments of the content 
of the remote kernel memory.

An attacker may use this flaw to remotely sniff what is going into
the host's memory, especially network packets that it sees, and
obtain useful information such as POP passwords, HTTP authentication
fields, and so on.


Solution : Contact your vendor for a fix. If the remote host is running
           Linux 2.0, upgrade to Linux 2.0.40.
See also : http://www.cartel-securite.fr/pbiondi/adv/CARTSA-20030314-icmpleak
           http://www.kb.cert.org/vuls/id/471084
Risk factor : High";





 script_description(english:desc["english"]);
 
 summary["english"] = "icmpleak check";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencies("os_fingerprint.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}




#
# The script code starts here
# 

include('global_settings.inc');


if(islocalhost())exit(0);
if ( !thorough_tests) exit(0);

os = get_kb_item("Host/OS/icmp");
if ( os && !egrep(pattern:"Linux 2\.[0-2]", string:os) ) exit(0);


# Sends a fragmented ping packet
function send_frag_ping()
{
	local_var ip, icmp;

	ip = forge_ip_packet(ip_hl : 5, ip_v : 4, ip_tos: 0, ip_len : 46,
ip_id: rand(), ip_off: IP_MF, ip_ttl: 64, ip_p : IPPROTO_ICMP, ip_src : this_host(), ip_dst:get_host_ip());

	icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:0, icmp_id:0, data:crap(length:18, data:"X"));

	filter = string("icmp and src ", get_host_ip(), " and icmp[0] = 11 and icmp[1] = 1 and icmp[36]=88 and icmp[37]=88");
	
	for(i=0;i<5;i++)
	{
	 send_packet(icmp, pcap_active:FALSE);
	 sleep(1);
	}
	
	rep = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:31);
	if(rep) return(rep);
	else return NULL;
}


rep = send_frag_ping();
if( rep != NULL )
{
 start = 20 + 8 + 28;
 end   = strlen(rep);
 for(i = start ; i < end ; i ++)
 {
  if(rep[i] != "X" )
  {
    security_hole(proto:"icmp", port:0);
    exit(0);
  }
 }
}
