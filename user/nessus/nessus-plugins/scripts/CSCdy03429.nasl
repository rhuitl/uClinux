#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Script License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
#


if(description)
{
 script_id(11056);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0014");
 script_bugtraq_id(5328);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2002-0813");

 name["english"] = "CSCdy03429";

 script_name(english:name["english"]);

 desc["english"] = "

Trivial File Transfer Protocol (TFTP) is a protocol which allows for 
easy transfer of files between network connected devices. 

A vulnerability has been discovered in the processing of filenames within
a TFTP read request when Cisco IOS is configured to act as a TFTP server

This vulnerability is documented as Cisco Bug ID CSCdy03429

Solution : 
http://www.cisco.com/warp/public/707/ios-tftp-long-filename-pub.shtml
Risk factor : High

*** As Nessus solely relied on the banner of the remote host
*** this might be a false positive
";
 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2002 Renaud Deraison");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc");
 exit(0);
}


# The code starts here
ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);

# IOSes 11.1 to 11.3 are vulnerable
if(egrep(string:os, pattern:".* 11\.[1-3][^0-9].*"))
	security_hole(port:161, proto:"udp");

