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
 script_id(10983);
 script_bugtraq_id(4191);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0339");

 name["english"] = "CSCdu20643";

 script_name(english:name["english"]);

 desc["english"] = "
If the remote device has Cisco Express Forwarding (CEF) enabled,
it may leak information from previous packets that have been
handled by the device.

An attacker may use this flaw to sniff your network remotely

This vulnerability is documented as Cisco Bug ID CSCdu20643.

Solution : http://www.cisco.com/warp/public/707/IOS-CEF-pub.shtml
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
# 11.1CC
if(egrep(string:os, pattern:"((11\.1\(([0-9]|[1-2][0-9]|3[0-5])\)|11\.1)CC[0-9]*|11\.1\(36\)CC[0-2]),"))ok=1;

# 12.0
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0),"))ok=1;

# 12.0S
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-8])\)|12\.0)S[0-9]*,"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-8])\)|12\.0)ST[0-9]*,"))ok=1;

# 12.0T
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)T[0-9]*,"))ok=1;

# 12.0W5
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)W5[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\([0-9]\)|12\.1),"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(12\.1\([0-8]\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EC
if(egrep(string:os, pattern:"(12\.1\([0-9]\)|12\.1)EC[0-9]*,"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)T[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XM[0-9]*|12\.1\(5\)XM[0-5]),"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\([0-2]\)|12\.2),"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)S[0-9]*,"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)T[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
