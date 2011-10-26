#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      No vuln in SecurityFocus.  SecurityFocus assigned new BugtraqID.  Added BugtraqID
#


if(description)
{
 script_id(10984);
 script_bugtraq_id(3547);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2001-0895");

 name["english"] = "CSCdu81936";

 script_name(english:name["english"]);

 desc["english"] = "

It is possible to send an Address Resolution Protocol (ARP) packet on 
a local broadcast interface (for example, Ethernet, cable, Token 
Ring, FDDI) which could cause a router or switch running specific 
versions of Cisco IOS® Software Release to stop sending and receiving 
ARP packets on the local router interface.  This will in a short time 
cause the router and local hosts to be unable to send packets to each 
other. ARP packets  received by the router for the router's own 
interface address but a different Media Access Control (MAC) address 
will overwrite the router's MAC address in the ARP table with the one 
from the received ARP packet.  This was demonstrated to attendees of  
the  Black Hat conference and should be considered to be public 
knowledge.  This attack is only successful against devices on the 
segment local to the attacker or attacking host.
This vulnerability is documented in Cisco Bug ID CSCdu81936.

A local attacker may use this flaw to prevent your network from
working properly.


Solution : 
http://www.cisco.com/warp/public/707/IOS-arp-overwrite-vuln-pub.shtml
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
# cisco800
if(ereg(string:hardware, pattern:"^cisco80[0-9]$"))ok=1;

# ciscoUBR900
if(ereg(string:hardware, pattern:"^ciscoUBR90[0-9]$"))ok=1;

# cisco1000
if(ereg(string:hardware, pattern:"^cisco10[0-9][0-9]$"))ok=1;

# cisco1400
if(ereg(string:hardware, pattern:"^cisco14[0-9][0-9]$"))ok=1;

# cisco1500
if(ereg(string:hardware, pattern:"^cisco15[0-9][0-9]$"))ok=1;

# cisco1600
if(ereg(string:hardware, pattern:"^cisco16[0-9][0-9]$"))ok=1;

# cisco1700
if(ereg(string:hardware, pattern:"^cisco17[0-9][0-9]$"))ok=1;

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

# ciscoUBR7200
if(ereg(string:hardware, pattern:"^ciscoUBR72[0-9][0-9]$"))ok=1;

# cisco7500
if(ereg(string:hardware, pattern:"^cisco75[0-9][0-9]$"))ok=1;

# cisco12000
if(ereg(string:hardware, pattern:"^cisco12[0-9][0-9][0-9]$"))ok=1;

# ciscoLS1010
if(ereg(string:hardware, pattern:"^ciscoLS101[0-9]$"))ok=1;

# catalyst29[0-9][0-9][^0-9]*
if(ereg(string:hardware, pattern:"^catalyst29[0-9][0-9][^0-9]*$"))ok=1;

# catalyst35[0-9][0-9][^0-9]*
if(ereg(string:hardware, pattern:"^catalyst35[0-9][0-9][^0-9]*$"))ok=1;

# catalyst4kGateway
if(ereg(string:hardware, pattern:"^catalyst4kGateway$"))ok=1;

# catalyst5kRsfc
if(ereg(string:hardware, pattern:"^catalyst5kRsfc$"))ok=1;

# catalyst6kMsfc
if(ereg(string:hardware, pattern:"^catalyst6kMsfc$"))ok=1;

# catalyst6kMsfc2
if(ereg(string:hardware, pattern:"^catalyst6kMsfc2$"))ok=1;

# catalyst85[0-9][0-9][^0-9]*
if(ereg(string:hardware, pattern:"^catalyst85[0-9][0-9][^0-9]*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 11.1
if(egrep(string:os, pattern:"(11\.1\([0-9]*\)|11\.1),"))ok=1;

# 11.2
if(egrep(string:os, pattern:"(11\.2\(([0-9]|1[0-2])\)|11\.2),"))ok=1;

# 11.2P
if(egrep(string:os, pattern:"(11\.2\(([0-9]|1[0-1])\)|11\.2)P[0-9]*,"))ok=1;

# 11.3
if(egrep(string:os, pattern:"(11\.3\([0-2]\)|11\.3),"))ok=1;

# 11.3T
if(egrep(string:os, pattern:"(11\.3\([0-2]\)|11\.3)T[0-9]*,"))ok=1;

# 12.0
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-9])\)|12\.0),"))ok=1;

# 12.0DA
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)DA[0-9]*,"))ok=1;

# 12.0DB
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)DB[0-9]*,"))ok=1;

# 12.0DC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)DC[0-9]*,"))ok=1;

# 12.0S
if(egrep(string:os, pattern:"(12\.0\(([0-9]|[1-1][0-9]|2[0-0])\)|12\.0)S[0-9]*,"))ok=1;

# 12.0SC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SC[0-9]*,"))ok=1;

# 12.0SL
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SL[0-9]*,"))ok=1;

# 12.0SP
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-9])\)|12\.0)SP[0-9]*,"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-9])\)|12\.0)ST[0-9]*,"))ok=1;

# 12.0T
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)T[0-9]*,"))ok=1;

# 12.0W5
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-9])\)|12\.0)W5[0-9]*,"))ok=1;

# 12.0WC
if(egrep(string:os, pattern:"((12\.0\([0-4]\)|12\.0)WC[0-9]*|12\.0\(5\)WC[0-2]),"))ok=1;

# 12.0XA
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XA[0-9]*,"))ok=1;

# 12.0XB
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XB[0-9]*,"))ok=1;

# 12.0XC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XC[0-9]*,"))ok=1;

# 12.0XD
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XD[0-9]*,"))ok=1;

# 12.0XE
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XE[0-9]*,"))ok=1;

# 12.0XF
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XF[0-9]*,"))ok=1;

# 12.0XG
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XG[0-9]*,"))ok=1;

# 12.0XH
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XH[0-9]*,"))ok=1;

# 12.0XI
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XI[0-9]*,"))ok=1;

# 12.0XJ
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XJ[0-9]*,"))ok=1;

# 12.0XK
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XK[0-9]*,"))ok=1;

# 12.0XL
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XL[0-9]*,"))ok=1;

# 12.0XM
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XM[0-9]*,"))ok=1;

# 12.0XN
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XN[0-9]*,"))ok=1;

# 12.0XP
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XP[0-9]*,"))ok=1;

# 12.0XQ
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XQ[0-9]*,"))ok=1;

# 12.0XR
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XR[0-9]*,"))ok=1;

# 12.0XS
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XS[0-9]*,"))ok=1;

# 12.0XU
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XU[0-9]*,"))ok=1;

# 12.0XV
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XV[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-0])\)|12\.1),"))ok=1;

# 12.1AA
if(egrep(string:os, pattern:"(12\.1\([0-9]\)|12\.1)AA[0-9]*,"))ok=1;

# 12.1DA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)DA[0-9]*,"))ok=1;

# 12.1DB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)DB[0-9]*,"))ok=1;

# 12.1DC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)DC[0-9]*,"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-0])\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EC
if(egrep(string:os, pattern:"(12\.1\([0-8]\)|12\.1)EC[0-9]*,"))ok=1;

# 12.1EX
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)EX[0-9]*,"))ok=1;

# 12.1EY
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)EY[0-9]*,"))ok=1;

# 12.1EZ
if(egrep(string:os, pattern:"(12\.1\([0-5]\)|12\.1)EZ[0-9]*,"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)T[0-9]*,"))ok=1;

# 12.1XA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XA[0-9]*,"))ok=1;

# 12.1XB
if(egrep(string:os, pattern:"((12\.1\([0-1]\)|12\.1)XB[0-9]*|12\.1\(2\)XB[0-1]),"))ok=1;

# 12.1XC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XC[0-9]*,"))ok=1;

# 12.1XD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XD[0-9]*,"))ok=1;

# 12.1XE
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XE[0-9]*,"))ok=1;

# 12.1XF
if(egrep(string:os, pattern:"((12\.1\([0-1]\)|12\.1)XF[0-9]*|12\.1\(2\)XF[0-4]),"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"((12\.1\([0-2]\)|12\.1)XG[0-9]*|12\.1\(3\)XG[0-5]),"))ok=1;

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

# 12.1XM
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XM[0-9]*|12\.1\(5\)XM[0-5]),"))ok=1;

# 12.1XP
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XP[0-9]*,"))ok=1;

# 12.1XQ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XQ[0-9]*,"))ok=1;

# 12.1XR
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XR[0-9]*,"))ok=1;

# 12.1XS
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XS[0-9]*,"))ok=1;

# 12.1XT
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XT[0-9]*,"))ok=1;

# 12.1XU
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XU[0-9]*,"))ok=1;

# 12.1XV
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XV[0-9]*,"))ok=1;

# 12.1XW
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XW[0-9]*,"))ok=1;

# 12.1XX
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XX[0-9]*,"))ok=1;

# 12.1YA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YA[0-9]*,"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YB[0-9]*|12\.1\(5\)YB[0-4]),"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YC[0-9]*|12\.1\(5\)YC[0-1]),"))ok=1;

# 12.1YD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YD[0-9]*,"))ok=1;

# 12.1YE
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YE[0-9]*|12\.1\(5\)YE[0-3]),"))ok=1;

# 12.1YF
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YF[0-9]*|12\.1\(5\)YF[0-2]),"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\([0-4]\)|12\.2),"))ok=1;

# 12.2DD
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)DD[0-9]*|12\.2\(2\)DD[0-0]),"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"(12\.2\([0-6]\)|12\.2)T[0-9]*,"))ok=1;

# 12.2XA
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XA[0-9]*|12\.2\(2\)XA[0-3]),"))ok=1;

# 12.2XB
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XB[0-9]*|12\.2\(2\)XB[0-1]),"))ok=1;

# 12.2XC
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XC[0-9]*|12\.2\(2\)XC[0-0]),"))ok=1;

# 12.2XD
if(egrep(string:os, pattern:"((12\.2\([0-0]\)|12\.2)XD[0-9]*|12\.2\(1\)XD[0-2]),"))ok=1;

# 12.2XE
if(egrep(string:os, pattern:"((12\.2\([0-0]\)|12\.2)XE[0-9]*|12\.2\(1\)XE[0-1]),"))ok=1;

# 12.2XG
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XG[0-9]*|12\.2\(2\)XG[0-0]),"))ok=1;

# 12.2XH
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XH[0-9]*|12\.2\(2\)XH[0-1]),"))ok=1;

# 12.2XI
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XI[0-9]*|12\.2\(2\)XI[0-0]),"))ok=1;

# 12.2XJ
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XJ[0-9]*|12\.2\(2\)XJ[0-1]),"))ok=1;

# 12.2XK
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XK[0-9]*|12\.2\(2\)XK[0-4]),"))ok=1;

# 12.2XQ
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XQ[0-9]*|12\.2\(2\)XQ[0-1]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
