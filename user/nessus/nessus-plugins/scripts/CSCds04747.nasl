#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#


if(description)
{
 script_id(10976);
 script_bugtraq_id(2682);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2001-0328");

 name["english"] = "CSCds04747";

 script_name(english:name["english"]);

 desc["english"] = "

Cisco IOS Software contains a flaw that permits the successful 
prediction of TCP Initial Sequence Numbers.

This vulnerability is present in all released versions of Cisco IOS 
software running on Cisco routers and switches. It only affects the 
security of TCP connections that originate or terminate on the 
affected Cisco device itself; it does not apply to TCP traffic 
forwarded through the affected device in transit between two other 
hosts.


This vulnerability is documented as Cisco bug ID CSCds04747.

Solution : 
http://www.cisco.com/warp/public/707/ios-tcp-isn-random-pub.shtml
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




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 11.0
if(egrep(string:os, pattern:"(11\.0\(([0-9]|[1-1][0-9]|2[0-1])\)|11\.0),"))ok=1;

# 11.1
if(egrep(string:os, pattern:"(11\.1\(([0-9]|[1-1][0-9]|2[0-3])\)|11\.1),"))ok=1;

# 11.1AA
if(egrep(string:os, pattern:"(11\.1\([0-9]*\)|11\.1)AA[0-9]*,"))ok=1;

# 11.1CA
if(egrep(string:os, pattern:"((11\.1\(([0-9]|[1-2][0-9]|3[0-5])\)|11\.1)CA[0-9]*|11\.1\(36\)CA[0-0]),"))ok=1;

# 11.1CC
if(egrep(string:os, pattern:"((11\.1\(([0-9]|[1-2][0-9]|3[0-5])\)|11\.1)CC[0-9]*|11\.1\(36\)CC[0-0]),"))ok=1;

# 11.1CT
if(egrep(string:os, pattern:"(11\.1\([0-9]*\)|11\.1)CT[0-9]*,"))ok=1;

# 11.1IA
if(egrep(string:os, pattern:"((11\.1\(([0-9]|[1-1][0-9]|2[0-7])\)|11\.1)IA[0-9]*|11\.1\(28\)IA[0-0]),"))ok=1;

# 11.2
if(egrep(string:os, pattern:"(11\.2\(([0-9]|[1-1][0-9]|2[0-4])\)|11\.2),"))ok=1;

# 11.2BC
if(egrep(string:os, pattern:"(11\.2\([0-9]*\)|11\.2)BC[0-9]*,"))ok=1;

# 11.2F
if(egrep(string:os, pattern:"(11\.2\([0-9]*\)|11\.2)F[0-9]*,"))ok=1;

# 11.2GS
if(egrep(string:os, pattern:"(11\.2\([0-9]*\)|11\.2)GS[0-9]*,"))ok=1;

# 11.2P
if(egrep(string:os, pattern:"(11\.2\(([0-9]|[1-1][0-9]|2[0-4])\)|11\.2)P[0-9]*,"))ok=1;

# 11.2SA
if(egrep(string:os, pattern:"(11\.2\([0-9]*\)|11\.2)SA[0-9]*,"))ok=1;

# 11.2WA3
if(egrep(string:os, pattern:"(11\.2\([0-9]*\)|11\.2)WA3[0-9]*,"))ok=1;

# 11.2XA
if(egrep(string:os, pattern:"(11\.2\([0-9]*\)|11\.2)XA[0-9]*,"))ok=1;

# 11.3
if(egrep(string:os, pattern:"(11\.3\(([0-9]|1[0-0])\)|11\.3),"))ok=1;

# 11.3AA
if(egrep(string:os, pattern:"(11\.3\(([0-9]|1[0-0])\)|11\.3)AA[0-9]*,"))ok=1;

# 11.3DA
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3)DA[0-9]*,"))ok=1;

# 11.3DB
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3)DB[0-9]*,"))ok=1;

# 11.3HA
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3)HA[0-9]*,"))ok=1;

# 11.3MA
if(egrep(string:os, pattern:"((11\.3\([0-0]\)|11\.3)MA[0-9]*|11\.3\(1\)MA[0-7]),"))ok=1;

# 11.3NA
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3)NA[0-9]*,"))ok=1;

# 11.3T
if(egrep(string:os, pattern:"((11\.3\(([0-9]|1[0-0])\)|11\.3)T[0-9]*|11\.3\(11\)T[0-0]),"))ok=1;

# 11.3WA4
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3)WA4[0-9]*,"))ok=1;

# 11.3XA
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3)XA[0-9]*,"))ok=1;

# 12.0
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-4])\)|12\.0),"))ok=1;

# 12.0DA
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)DA[0-9]*,"))ok=1;

# 12.0DB
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)DB[0-9]*,"))ok=1;

# 12.0DC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)DC[0-9]*,"))ok=1;

# 12.0S
if(egrep(string:os, pattern:"((12\.0\(([0-9]|1[0-3])\)|12\.0)S[0-9]*|12\.0\(14\)S[0-0]),"))ok=1;

# 12.0SC
if(egrep(string:os, pattern:"((12\.0\(([0-9]|1[0-4])\)|12\.0)SC[0-9]*|12\.0\(15\)SC[0-0]),"))ok=1;

# 12.0SL
if(egrep(string:os, pattern:"((12\.0\(([0-9]|1[0-3])\)|12\.0)SL[0-9]*|12\.0\(14\)SL[0-0]),"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"((12\.0\(([0-9]|1[0-0])\)|12\.0)ST[0-9]*|12\.0\(11\)ST[0-1]),"))ok=1;

# 12.0SX
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SX[0-9]*,"))ok=1;

# 12.0T
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)T[0-9]*,"))ok=1;

# 12.0W5
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-2])\)|12\.0)W5[0-9]*,"))ok=1;

# 12.0WT
if(egrep(string:os, pattern:"((12\.0\(([0-9]|1[0-2])\)|12\.0)WT[0-9]*|12\.0\(13\)WT[0-5]),"))ok=1;

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

# 12.0QR
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)QR[0-9]*,"))ok=1;

# 12.0XS
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XS[0-9]*,"))ok=1;

# 12.0XU
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XU[0-9]*,"))ok=1;

# 12.0XV
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XV[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\([0-6]\)|12\.1),"))ok=1;

# 12.1AA
if(egrep(string:os, pattern:"(12\.1\([0-6]\)|12\.1)AA[0-9]*,"))ok=1;

# 12.1DA
if(egrep(string:os, pattern:"(12\.1\([0-5]\)|12\.1)DA[0-9]*,"))ok=1;

# 12.1CD
if(egrep(string:os, pattern:"(12\.1\([0-3]\)|12\.1)CD[0-9]*,"))ok=1;

# 12.DB
if(egrep(string:os, pattern:"(12\.\([0-4]\)|12\.)DB[0-9]*,"))ok=1;

# 12.1DC
if(egrep(string:os, pattern:"(12\.1\([0-4]\)|12\.1)DC[0-9]*,"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(12\.1\([0-5]\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EC
if(egrep(string:os, pattern:"(12\.1\([0-5]\)|12\.1)EC[0-9]*,"))ok=1;

# 12.1EX
if(egrep(string:os, pattern:"(12\.1\([0-4]\)|12\.1)EX[0-9]*,"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)T[0-9]*|12\.1\(5\)T[0-4]),"))ok=1;

# 12.1XA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XA[0-9]*,"))ok=1;

# 12.1XB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XB[0-9]*,"))ok=1;

# 12.1XC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XC[0-9]*,"))ok=1;

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

# 12.1XK
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XK[0-9]*,"))ok=1;

# 12.1XL
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XL[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XM[0-9]*,"))ok=1;

# 12.1XP
if(egrep(string:os, pattern:"((12\.1\([0-2]\)|12\.1)XP[0-9]*|12\.1\(3\)XP[0-2]),"))ok=1;

# 12.1XQ
if(egrep(string:os, pattern:"((12\.1\([0-2]\)|12\.1)XQ[0-9]*|12\.1\(3\)XQ[0-2]),"))ok=1;

# 12.1XR
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XR[0-9]*|12\.1\(5\)XR[0-0]),"))ok=1;

# 12.1XT
if(egrep(string:os, pattern:"((12\.1\([0-2]\)|12\.1)XT[0-9]*|12\.1\(3\)XT[0-0]),"))ok=1;

# 12.1XU
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XU[0-9]*|12\.1\(5\)XU[0-0]),"))ok=1;

# 12.1XV
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XV[0-9]*|12\.1\(5\)XV[0-0]),"))ok=1;

# 12.1XW
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XW[0-9]*|12\.1\(5\)XW[0-1]),"))ok=1;

# 12.1XY
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XY[0-9]*|12\.1\(5\)XY[0-3]),"))ok=1;

# 12.1XZ
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XZ[0-9]*|12\.1\(5\)XZ[0-1]),"))ok=1;

# 12.1YA
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YA[0-9]*|12\.1\(5\)YA[0-0]),"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"(12\.1\([0-4]\)|12\.1)YB[0-9]*,"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YC[0-9]*|12\.1\(5\)YC[0-0]),"))ok=1;

# 12.1YD
if(egrep(string:os, pattern:"(12\.1\([0-4]\)|12\.1)YD[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");
