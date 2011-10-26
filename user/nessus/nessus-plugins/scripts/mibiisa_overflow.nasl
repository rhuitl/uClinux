#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# XXXXXX This script should be rewritten to actually check for the overflow.
#


if(description)
{
 script_id(11335);
 script_bugtraq_id(4932, 4933);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0797", "CVE-2002-0796");
 
 name["english"] = "mibiisa overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running mibiisa. 

There is a buffer overflow in older versions of
this software, which may allow an attacker to gain
a root shell on this host

*** Nessus did not actually check for this vulnerability,
*** so this might be a false positive

Solution : See Sun security bulletin #00219";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of mibiisa";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("snmp_settings.nasl", "os_fingerprint.nasl");
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

os = get_kb_item("Host/OS/icmp");
if( os )
{
 if("Solaris 9" >< os)exit(0);
}


#--------------------------------------------------------------------#
# Forges an SNMP GET NEXT packet                                     #
#--------------------------------------------------------------------#
function get_next(community, id, object)
{
 len = strlen(community);
#display("len : ", len, "\n");
 len = len % 256;
 
 tot_len = 4 + strlen(community) + 12 + strlen(object) + 4;
# display(hex(tot_len), "\n");
 _r = raw_string(0x30, tot_len, 0x02, 0x01, 0x00, 0x04, len);
 o_len = strlen(object) + 2;
 
 a_len = 13 + strlen(object);
 _r = _r + community + raw_string( 0xA1,
	a_len, 0x02, 0x01, id,   0x02, 0x01, 0x00, 0x02,
	0x01, 0x00, 0x30,o_len) + object + raw_string(0x05, 0x00);
# display("len : ", strlen(_r), "\n");
 return(_r);
}



community = get_kb_item("SNMP/community");
if(!community)community = "public";


port = 32789;

soc = open_sock_udp(port);

first = raw_string(0x30, 0x82, 0x00, 
		   0x0B, 0x06, 0x07, 0x2b, 0x06, 0x01, 0x02, 0x01,
		   0x01, 0x01);
		  
id = 2;
req = get_next(id:id, community:community, object:first);

send(socket:soc, data:req);
r = recv(socket:soc, length:1025);
if(strlen(r) > 0)security_hole(port:port, proto:"udp");
