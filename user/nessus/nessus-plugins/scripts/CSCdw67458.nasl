#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
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
 script_id(10987);
 script_bugtraq_id(4088);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0012", "CVE-2002-0013");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0008");

 name["english"] = "CSCdw67458";

 script_name(english:name["english"]);

 desc["english"] = "

There is a vulnerability in the way the remote device handles
SNMP messages. An attacker may use this flaw to crash the remote
device continuously

This vulnerability is documented as Cisco bug ID CSCdw67458.

Solution : 
http://www.cisco.com/warp/public/707/cisco-malformed-snmp-msgs-non-ios-pub.shtml

Reference : http://online.securityfocus.com/archive/1/255807

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
# catalyst.*
if(ereg(string:hardware, pattern:"^catalyst.*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this CatOS ?
if(!egrep(pattern:".*Cisco Catalyst Operating System.*", string:os))exit(0);
# 4.5
if(egrep(string:os, pattern:"(4\.5\(([0-9]|1[0-2])\)|4\.5),"))ok=1;

# 5.1CSX
if(egrep(string:os, pattern:"(5\.1\([0-0]\)|5\.1)CSX[0-9]*,"))ok=1;

# 5.1
if(egrep(string:os, pattern:"(5\.1\([0-1]\)|5\.1),"))ok=1;

# 5.2CSX
if(egrep(string:os, pattern:"(5\.2\([0-2]\)|5\.2)CSX[0-9]*,"))ok=1;

# 5.2
if(egrep(string:os, pattern:"(5\.2\([0-6]\)|5\.2),"))ok=1;

# 5.3CSX
if(egrep(string:os, pattern:"(5\.3\([0-5]\)|5\.3)CSX[0-9]*,"))ok=1;

# 5.4
if(egrep(string:os, pattern:"(5\.4\([0-3]\)|5\.4),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\([0-6]\)|5\.5),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\(([0-9]|1[0-2])\)|5\.5),"))ok=1;

# 6.1
if(egrep(string:os, pattern:"(6\.1\([0-3]\)|6\.1),"))ok=1;

# 6.2
if(egrep(string:os, pattern:"(6\.2\([0-2]\)|6\.2),"))ok=1;

# 6.3X
if(egrep(string:os, pattern:"((6\.3\([0-2]\)|6\.3)X[0-9]*|6\.3\(3\)X[0-0]),"))ok=1;

# 6.3
if(egrep(string:os, pattern:"(6\.3\([0-4]\)|6\.3),"))ok=1;

# 7.1
if(egrep(string:os, pattern:"(7\.1\([0-1]\)|7\.1),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
