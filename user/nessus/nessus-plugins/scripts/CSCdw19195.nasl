#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#


if(description)
{
 script_id(10986);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-t-0008");
 script_bugtraq_id(3064);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2001-0554");

 name["english"] = "CSCdw19195";

 script_name(english:name["english"]);

 desc["english"] = "
Some Cisco Catalyst switches, running certain CatOS based software
releases, have a vulnerability wherein a buffer overflow in the telnet
option handling can cause the telnet daemon to crash and result in a
switch reload. This vulnerability can be exploited to initiate a 
denial of service (DoS) attack.

This vulnerability is documented as Cisco bug ID CSCdw19195.

Solution : 
http://www.cisco.com/warp/public/707/catos-telrcv-vuln-pub.shtml

Reference : http://online.securityfocus.com/archive/1/252833

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
# catalyst8500
if(ereg(string:hardware, pattern:"^catalyst85[0-9][0-9]$"))ok=1;

# catalyst4kGateway
if(ereg(string:hardware, pattern:"^catalyst4kGateway$"))ok=1;

# catalyst3[0-9][0-9][0-9][^0-9]*
if(ereg(string:hardware, pattern:"^catalyst3[0-9][0-9][0-9][^0-9]*$"))ok=1;

# catalyst29[0-9][0-9][^0-9]*
if(ereg(string:hardware, pattern:"^catalyst29[0-9][0-9][^0-9]*$"))ok=1;

# catalyst19[0-9][0-9][^0-9]*
if(ereg(string:hardware, pattern:"^catalyst19[0-9][0-9][^0-9]*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this CatOS ?
if(!egrep(pattern:".*Cisco Catalyst Operating System.*", string:os))exit(0);
# 4.5
if(egrep(string:os, pattern:"(4\.5\(([0-9]|1[0-2])\)|4\.5),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\(([0-9]|1[0-2])\)|5\.5),"))ok=1;

# 6.3
if(egrep(string:os, pattern:"(6\.3\([0-3]\)|6\.3),"))ok=1;

# 7.1
if(egrep(string:os, pattern:"(7\.1\([0-1]\)|7\.1),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
