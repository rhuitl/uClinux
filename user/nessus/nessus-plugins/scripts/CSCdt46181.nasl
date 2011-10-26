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
 script_id(10979);
 script_bugtraq_id(3022);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2001-1183");

 name["english"] = "CSCdt46181";

 script_name(english:name["english"]);

 desc["english"] = "

Point-to-Point Tunneling Protocol (PPTP) allows users to tunnel to an 
Internet Protocol (IP) network using a Point-to-Point Protocol (PPP). 
The protocol is described in RFC2637.

PPTP implementation using Cisco IOS® software releases contains a 
vulnerability that will crash a router if it receives a malformed or 
crafted PPTP packet. To expose this vulnerability, PPTP must be 
enabled on the router. PPTP is disabled by default. No additional 
special conditions are required.

An attacker may use this issue to prevent your network
from working properly

This vulnerability is documented as Cisco Bug ID CSCdt46181

Solution : 
http://www.cisco.com/warp/public/707/PPTP-vulnerability-pub.html
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




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.1E
if(egrep(string:os, pattern:"(12\.1\([0-8]\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EZ
if(egrep(string:os, pattern:"((12\.1\([0-5]\)|12\.1)EZ[0-9]*|12\.1\(6\)EZ[0-1]),"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)T[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XM[0-9]*|12\.1\(5\)XM[0-3]),"))ok=1;

# 12.1XV
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XV[0-9]*|12\.1\(5\)XV[0-2]),"))ok=1;

# 12.1YA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YA[0-9]*,"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YB[0-9]*|12\.1\(5\)YB[0-3]),"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YC[0-9]*|12\.1\(5\)YC[0-0]),"))ok=1;

# 12.1YD
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YD[0-9]*|12\.1\(5\)YD[0-1]),"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\([0-2]\)|12\.2),"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)T[0-9]*,"))ok=1;

# 12.2XA
if(egrep(string:os, pattern:"(12\.2\([0-1]\)|12\.2)XA[0-9]*,"))ok=1;

# 12.2XD
if(egrep(string:os, pattern:"((12\.2\([0-0]\)|12\.2)XD[0-9]*|12\.2\(1\)XD[0-0]),"))ok=1;

# 12.2XE
if(egrep(string:os, pattern:"(12\.2\([0-0]\)|12\.2)XE[0-9]*,"))ok=1;

# 12.2XH
if(egrep(string:os, pattern:"(12\.2\([0-0]\)|12\.2)XH[0-9]*,"))ok=1;

# 12.2XQ
if(egrep(string:os, pattern:"(12\.2\([0-0]\)|12\.2)XQ[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
