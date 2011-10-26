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
 script_id(10978);
 script_bugtraq_id(2072);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2001-0041");

 name["english"] = "CSCds66191";

 script_name(english:name["english"]);

 desc["english"] = "
A series of failed telnet authentication attempts to the switch can 
cause the Catalyst Switch to fail to pass traffic or accept 
management connections until the system is rebooted or a power cycle 
is performed. All types of telnet authentication are affected, 
including Kerberized telnet, and AAA authentication.

This vulnerability is documented as Cisco bug ID CSCds66191.

Solution : 
http://www.cisco.com/warp/public/707/catalyst-memleak-pub.shtml
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
if(egrep(string:os, pattern:"(4\.5\([0-9]\)|4\.5),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\([0-4]\)|5\.5),"))ok=1;

# 6.3
if(egrep(string:os, pattern:"(6\.3\([0-2]\)|6\.3),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
