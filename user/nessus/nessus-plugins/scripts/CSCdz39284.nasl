#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
#


if(description)
{
 script_id(11380);
 script_bugtraq_id(6904);
 # script_cve_id("CVE-MAP-NOMATCH");
 # NOTE: no CVE id currently assigned (jfs, december 2003)
 # Review http://cve.mitre.org/cve/refs/refmap/source-CISCO.html
 # in the future to see if this gets updated

 script_version("$Revision: 1.5 $");

 name["english"] = "CSCdz39284, CSCdz41124";

 script_name(english:name["english"]);

 desc["english"] = "

It is possible to make the remote IOS crash when sending
it malformed SIP packets.

These vulnerabilities are documented as CISCO bug id CSCdz39284 and
CSCdz41124.

Solution : See http://www.cisco.com/warp/public/707/cisco-sa-20030221-protos.shtml
Risk factor : High

*** As Nessus solely relied on the banner of the remote host
*** this might be a false positive
";
 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003 Renaud Deraison");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl",
			 "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc",
			  "CISCO/model");
 exit(0);
}


# The code starts here
ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);

# 12.2T
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-2])\)|12\.2)T[0-9]*|12\.2\(13\)T[0-0]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
