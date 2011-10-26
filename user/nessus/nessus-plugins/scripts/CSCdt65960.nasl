#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#


if(description)
{
 script_id(10981);
 script_bugtraq_id(2874);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2001-0757");

 name["english"] = "CSCdt65960";

 script_name(english:name["english"]);

 desc["english"] = "
The Cisco 6400 Access Concentrator Node Route Processor 2 (NRP2) 
module allows Telnet access when no password has been set. The 
correct response is to disallow any remote access to the module until 
the password has been set. This vulnerability may result in users 
gaining unintended access to secure systems.

This vulnerability is documented as Cisco bug ID CSCdt65960.

Solution : 
http://www.cisco.com/warp/public/707/6400-nrp2-telnet-vuln-pub.shtml
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




# Check for the required hardware...
#----------------------------------------------------------------
# cisco6400Nrp
if(ereg(string:hardware, pattern:"^cisco6400Nrp$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.1DC
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)DC[0-9]*|12\.1\(5\)DC[0-0]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
