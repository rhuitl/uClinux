#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
#


if(description)
{
 script_id(10971);
 script_bugtraq_id(3534);
 script_cve_id("CVE-2001-0861");
 script_version("$Revision: 1.7 $");

 name["english"] = "GSR ICMP unreachable";

 script_name(english:name["english"]);

 desc["english"] = "
It seems that the performance of the remote device might
be degraded by forcing it to send a large number of ICMP unreachable
packages.

An attacker may use this flaw to slow down your network.

Solution : 
http://www.cisco.com/warp/public/707/GSR-unreachables-pub.shtml
Risk factor : Medium

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
# cisco12000
if(ereg(string:hardware, pattern:"^cisco12[0-9][0-9][0-9]$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.0S
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-6])\)|12\.0)S[0-9]*,"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-5])\)|12\.0)ST[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");
