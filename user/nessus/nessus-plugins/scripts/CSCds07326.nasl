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
 script_id(10977);
 script_bugtraq_id(2804);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2001-0750");

 name["english"] = "CSCds07326";

 script_name(english:name["english"]);

 desc["english"] = "
Some security scanners can force a Cisco device to reload.

An attacker may use this flaw to prevent your network
from working properly.

This vulnerability is documented as Cisco Bug ID CSCds07326.

Solution : 
http://www.cisco.com/warp/public/707/ios-tcp-scanner-reload-pub.shtml
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
# ciscoIGS
if(ereg(string:hardware, pattern:"^ciscoIGS$"))ok=1;

# ciscoAGSplus
if(ereg(string:hardware, pattern:"^ciscoAGSplus$"))ok=1;

# cisco800
if(ereg(string:hardware, pattern:"^cisco80[0-9]$"))ok=1;

# ciscoABR900
if(ereg(string:hardware, pattern:"^ciscoABR90[0-9]$"))ok=1;

# cisco1000
if(ereg(string:hardware, pattern:"^cisco10[0-9][0-9]$"))ok=1;

# cisco2500
if(ereg(string:hardware, pattern:"^cisco25[0-9][0-9]$"))ok=1;

# cisco2600
if(ereg(string:hardware, pattern:"^cisco26[0-9][0-9]$"))ok=1;

# cisco3000
if(ereg(string:hardware, pattern:"^cisco30[0-9][0-9]$"))ok=1;

# cisco3600
if(ereg(string:hardware, pattern:"^cisco36[0-9][0-9]$"))ok=1;

# cisco3800
if(ereg(string:hardware, pattern:"^cisco38[0-9][0-9]$"))ok=1;

# cisco4000
if(ereg(string:hardware, pattern:"^cisco40[0-9][0-9]$"))ok=1;

# cisco4500
if(ereg(string:hardware, pattern:"^cisco45[0-9][0-9]$"))ok=1;

# cisco4700
if(ereg(string:hardware, pattern:"^cisco47[0-9][0-9]$"))ok=1;

# ciscoAS5200
if(ereg(string:hardware, pattern:"^ciscoAS52[0-9][0-9]$"))ok=1;

# ciscoAS5300
if(ereg(string:hardware, pattern:"^ciscoAS53[0-9][0-9]$"))ok=1;

# ciscoAS5800
if(ereg(string:hardware, pattern:"^ciscoAS58[0-9][0-9]$"))ok=1;

# cisco6400
if(ereg(string:hardware, pattern:"^cisco64[0-9][0-9]$"))ok=1;

# cisco7000
if(ereg(string:hardware, pattern:"^cisco70[0-9][0-9]$"))ok=1;

# cisco7200
if(ereg(string:hardware, pattern:"^cisco72[0-9][0-9]$"))ok=1;

# ciscoUBR7200
if(ereg(string:hardware, pattern:"^ciscoUBR72[0-9][0-9]$"))ok=1;

# cisco7500
if(ereg(string:hardware, pattern:"^cisco75[0-9][0-9]$"))ok=1;

# cisco12000
if(ereg(string:hardware, pattern:"^cisco12[0-9][0-9][0-9]$"))ok=1;

# catalyst2908xl
if(ereg(string:hardware, pattern:"^catalyst2908xl$"))ok=1;

# ciscoLS1010
if(ereg(string:hardware, pattern:"^ciscoLS101[0-9]$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.1DB
if(egrep(string:os, pattern:"(12\.1\([0-3]\)|12\.1)DB[0-9]*,"))ok=1;

# 12.1DC
if(egrep(string:os, pattern:"(12\.1\([0-3]\)|12\.1)DC[0-9]*,"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-4]\)|12\.1)T[0-9]*,"))ok=1;

# 12.1XB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XB[0-9]*,"))ok=1;

# 12.1XD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XD[0-9]*,"))ok=1;

# 12.1XE
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XE[0-9]*,"))ok=1;

# 12.1XF
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XF[0-9]*,"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XG[0-9]*,"))ok=1;

# 12.1XH
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XH[0-9]*,"))ok=1;

# 12.1XI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XI[0-9]*,"))ok=1;

# 12.1XJ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XJ[0-9]*,"))ok=1;

# 12.1XH
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XH[0-9]*,"))ok=1;

# 12.1XI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XI[0-9]*,"))ok=1;

# 12.1XJ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XJ[0-9]*,"))ok=1;

# 12.1XK
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XK[0-9]*,"))ok=1;

# 12.1XL
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XL[0-9]*,"))ok=1;

# 12.1XP
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XP[0-9]*,"))ok=1;

# 12.1XQ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XQ[0-9]*,"))ok=1;

# 12.1XS
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XS[0-9]*,"))ok=1;

# 12.1XT
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XT[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
