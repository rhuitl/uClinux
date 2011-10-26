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
 script_id(10975);
 script_bugtraq_id(1541);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2000-0700");

 name["english"] = "CSCdp35794";

 script_name(english:name["english"]);

 desc["english"] = "

A defect in Cisco IOS Software running on all models of Gigabit 
Switch Routers (GSRs) configured with Gigabit Ethernet or Fast 
Ethernet cards may cause packets to be forwarded without correctly 
evaluating configured access control lists (ACLs). In addition to 
circumventing the access control lists, it is possible to stop an 
interface from forwarding any packets, thus causing a denial of 
service.


This vulnerability is documented as Cisco bug ID CSCdp35794.

Solution : 
http://www.cisco.com/warp/public/707/gsraclbypassdos-pub.shtml
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
# cisco12008
if(ereg(string:hardware, pattern:"^cisco12008$"))ok=1;

# cisco12012
if(ereg(string:hardware, pattern:"^cisco12012$"))ok=1;

# cisco12016
if(ereg(string:hardware, pattern:"^cisco12016$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 11.2GS
if(egrep(string:os, pattern:"(11\.2\(([0-9]|1[0-8])\)|11\.2)GS[0-9]*,"))ok=1;

# 12.0S
if(egrep(string:os, pattern:"(12\.0\([0-8]\)|12\.0)S[0-9]*,"))ok=1;

# 12.0SC
if(egrep(string:os, pattern:"(12\.0\([0-8]\)|12\.0)SC[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
