#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
#


if(description)
{
 script_id(11791);
 script_bugtraq_id(8211);
 script_cve_id("CVE-2003-0567");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0010");

 script_version("$Revision: 1.7 $");

 name["english"] = "CISCO IOS Interface blocked by IPv4 Packet";

 script_name(english:name["english"]);

 desc["english"] = "

It is possible to block the remote router by sending malformed
IPv4 packets.

An attacker may use this flaw to render this router inoperable.

Solution : http://www.cisco.com/warp/public/707/cisco-sa-20030717-blocked.shtml
Risk factor : High
See also : http://www.cert.org/advisories/CA-2003-15.html

*** As Nessus solely relied on the banner of the remote host
*** this might be a false positive
";
 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003 Renaud Deraison");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl",
			 "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc");
 exit(0);
}


# The code starts here
ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 11.1CA
if(egrep(string:os, pattern:"((11\.1\(([0-9]|[1-2][0-9]|3[0-5])\)|11\.1)CA[0-9]*|11\.1\(36\)CA[0-3]),"))ok=1;

# 11.2
if(egrep(string:os, pattern:"(11\.2\(([0-9]|[1-1][0-9]|2[0-5])\)|11\.2),"))ok=1;

# 11.2P
if(egrep(string:os, pattern:"((11\.2\(([0-9]|[1-1][0-9]|2[0-5])\)|11\.2)P[0-9]*|11\.2\(26\)P[0-4]),"))ok=1;

# 11.3
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3),"))ok=1;

# 11.3T
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3)T[0-9]*,"))ok=1;

# 12.0
if(egrep(string:os, pattern:"(12\.0\(([0-9]|[1-1][0-9]|2[0-5])\)|12\.0),"))ok=1;

# 12.0DA
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)DA[0-9]*,"))ok=1;

# 12.0DB
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)DB[0-9]*,"))ok=1;

# 12.0DC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)DC[0-9]*,"))ok=1;

# 12.0S
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-3])\)|12\.0)S[0-9]*|12\.0\(24\)S[0-1]),"))ok=1;

# 12.0SC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SC[0-9]*,"))ok=1;

# 12.0SL
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SL[0-9]*,"))ok=1;

# 12.0SP
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SP[0-9]*,"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-0])\)|12\.0)ST[0-9]*|12\.0\(21\)ST[0-6]),"))ok=1;

# 12.0SX
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SX[0-9]*,"))ok=1;

# 12.0SY
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SY[0-9]*,"))ok=1;

# 12.0T
if(egrep(string:os, pattern:"((12\.0\([0-6]\)|12\.0)T[0-9]*|12\.0\(7\)T[0-2]),"))ok=1;

# 12.0W5
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)W5[0-9]*,"))ok=1;

# 12.0WC
if(egrep(string:os, pattern:"((12\.0\([0-4]\)|12\.0)WC[0-9]*|12\.0\(5\)WC[0-7]),"))ok=1;

# 12.0WT
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)WT[0-9]*,"))ok=1;

# 12.0X
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)X[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-8])\)|12\.1),"))ok=1;

# 12.1AA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)AA[0-9]*,"))ok=1;

# 12.1AX
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)AX[0-9]*,"))ok=1;

# 12.1AY
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-2])\)|12\.1)AY[0-9]*,"))ok=1;

# 12.1DA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)DA[0-9]*,"))ok=1;

# 12.1DB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)DB[0-9]*,"))ok=1;

# 12.1DC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)DC[0-9]*,"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-8])\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EA
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-2])\)|12\.1)EA[0-9]*,"))ok=1;

# 12.1EB
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-3])\)|12\.1)EB[0-9]*,"))ok=1;

# 12.1EC
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-8])\)|12\.1)EC[0-9]*,"))ok=1;

# 12.1EV
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-1])\)|12\.1)EV[0-9]*,"))ok=1;

# 12.1EW
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-8])\)|12\.1)EW[0-9]*,"))ok=1;

# 12.1EX
if(egrep(string:os, pattern:"((12\.1\(([0-9]|1[0-2])\)|12\.1)EX[0-9]*|12\.1\(13\)EX[0-1]),"))ok=1;

# 12.1EY
if(egrep(string:os, pattern:"((12\.1\(([0-9]|1[0-3])\)|12\.1)EY[0-9]*|12\.1\(14\)EY[0-3]),"))ok=1;

# 12.1YJ
if(egrep(string:os, pattern:"((12\.1\(([0-9]|1[0-3])\)|12\.1)YJ[0-9]*|12\.1\(14\)YJ[0-0]),"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)T[0-9]*|12\.1\(5\)T([0-9]|1[0-4])),"))ok=1;

# 12.1X
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)X[0-9]*,"))ok=1;

# 12.1XA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XA[0-9]*,"))ok=1;

# 12.1XC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XC[0-9]*,"))ok=1;

# 12.1XD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XD[0-9]*,"))ok=1;

# 12.1XH
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XH[0-9]*,"))ok=1;

# 12.1XI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XI[0-9]*,"))ok=1;

# 12.1XB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XB[0-9]*,"))ok=1;

# 12.1XF
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XF[0-9]*,"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XG[0-9]*,"))ok=1;

# 12.1XJ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XJ[0-9]*,"))ok=1;

# 12.1XL
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XL[0-9]*,"))ok=1;

# 12.1XP
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XP[0-9]*,"))ok=1;

# 12.1XR
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XR[0-9]*,"))ok=1;

# 12.1XT
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XT[0-9]*,"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YB[0-9]*,"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YC[0-9]*,"))ok=1;

# 12.1YD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YD[0-9]*,"))ok=1;

# 12.1YH
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YH[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XM[0-9]*,"))ok=1;

# 12.1XQ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XQ[0-9]*,"))ok=1;

# 12.1XV
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XV[0-9]*,"))ok=1;

# 12.1XU
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XU[0-9]*,"))ok=1;

# 12.1YE
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YE[0-9]*,"))ok=1;

# 12.1YF
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YF[0-9]*,"))ok=1;

# 12.1YI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YI[0-9]*,"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-6])\)|12\.2),"))ok=1;

# 12.2B
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-5])\)|12\.2)B[0-9]*|12\.2\(16\)B[0-0]),"))ok=1;

# 12.2BC
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)BC[0-9]*|12\.2\(15\)BC[0-0]),"))ok=1;

# 12.2BW
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BW[0-9]*,"))ok=1;

# 12.2BX
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-5])\)|12\.2)BX[0-9]*,"))ok=1;

# 12.2BZ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BZ[0-9]*,"))ok=1;

# 12.2CX
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)CX[0-9]*,"))ok=1;

# 12.2CY
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)CY[0-9]*,"))ok=1;

# 12.2DA
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-1])\)|12\.2)DA[0-9]*|12\.2\(12\)DA[0-2]),"))ok=1;

# 12.2DD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)DD[0-9]*,"))ok=1;

# 12.2JA
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-0])\)|12\.2)JA[0-9]*,"))ok=1;

# 12.2MB
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)MB[0-9]*|12\.2\(4\)MB([0-9]|1[0-1])),"))ok=1;

# 12.2MC
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-2])\)|12\.2)MC[0-9]*|12\.2\(13\)MC[0-0]),"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-3])\)|12\.2)S[0-9]*|12\.2\(14\)S[0-0]),"))ok=1;

# 12.2SY
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-3])\)|12\.2)SY[0-9]*|12\.2\(14\)SY[0-0]),"))ok=1;

# 12.2SZ
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-3])\)|12\.2)SZ[0-9]*|12\.2\(14\)SZ[0-1]),"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)T[0-9]*|12\.2\(15\)T[0-4]),"))ok=1;

# 12.2X
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)X[0-9]*,"))ok=1;

# 12.2Y
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)Y[0-9]*,"))ok=1;

# 12.2XA
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XA[0-9]*,"))ok=1;

# 12.2XS
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XS[0-9]*,"))ok=1;

# 12.2XD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XD[0-9]*,"))ok=1;

# 12.2XE
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XE[0-9]*,"))ok=1;

# 12.2XH
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XH[0-9]*,"))ok=1;

# 12.2XI
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XI[0-9]*,"))ok=1;

# 12.2XJ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XJ[0-9]*,"))ok=1;

# 12.2XK
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XK[0-9]*,"))ok=1;

# 12.2XL
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XL[0-9]*,"))ok=1;

# 12.2XM
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XM[0-9]*,"))ok=1;

# 12.2XQ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XQ[0-9]*,"))ok=1;

# 12.2XU
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XU[0-9]*,"))ok=1;

# 12.2XW
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XW[0-9]*,"))ok=1;

# 12.2YA
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YA[0-9]*,"))ok=1;

# 12.2YB
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YB[0-9]*,"))ok=1;

# 12.2YC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YC[0-9]*,"))ok=1;

# 12.2YF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YF[0-9]*,"))ok=1;

# 12.2YG
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YG[0-9]*,"))ok=1;

# 12.2YH
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YH[0-9]*,"))ok=1;

# 12.2YJ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YJ[0-9]*,"))ok=1;

# 12.2YT
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YT[0-9]*,"))ok=1;

# 12.2YN
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YN[0-9]*,"))ok=1;

# 12.2YO
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YO[0-9]*,"))ok=1;

# 12.2XB
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XB[0-9]*|12\.2\(2\)XB([0-9]|1[0-0])),"))ok=1;

# 12.2XC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XC[0-9]*,"))ok=1;

# 12.2XF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XF[0-9]*,"))ok=1;

# 12.2XG
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XG[0-9]*,"))ok=1;

# 12.2XN
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XN[0-9]*,"))ok=1;

# 12.2XT
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XT[0-9]*,"))ok=1;

# 12.2YD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YD[0-9]*,"))ok=1;

# 12.2YP
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-0])\)|12\.2)YP[0-9]*|12\.2\(11\)YP[0-0]),"))ok=1;

# 12.2YK
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YK[0-9]*,"))ok=1;

# 12.2YL
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YL[0-9]*,"))ok=1;

# 12.2YM
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YM[0-9]*,"))ok=1;

# 12.2YU
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YU[0-9]*,"))ok=1;

# 12.2YV
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YV[0-9]*,"))ok=1;

# 12.2YQ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YQ[0-9]*,"))ok=1;

# 12.2YR
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YR[0-9]*,"))ok=1;

# 12.2YS
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-4])\)|12\.2)YS[0-9]*,"))ok=1;

# 12.2YW
if(egrep(string:os, pattern:"((12\.2\([0-7]\)|12\.2)YW[0-9]*|12\.2\(8\)YW[0-1]),"))ok=1;

# 12.2YX
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-0])\)|12\.2)YX[0-9]*|12\.2\(11\)YX[0-0]),"))ok=1;

# 12.2YY
if(egrep(string:os, pattern:"((12\.2\([0-7]\)|12\.2)YY[0-9]*|12\.2\(8\)YY[0-2]),"))ok=1;

# 12.2YZ
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-0])\)|12\.2)YZ[0-9]*|12\.2\(11\)YZ[0-1]),"))ok=1;

# 12.2ZA
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-3])\)|12\.2)ZA[0-9]*|12\.2\(14\)ZA[0-1]),"))ok=1;

# 12.2ZB
if(egrep(string:os, pattern:"((12\.2\([0-7]\)|12\.2)ZB[0-9]*|12\.2\(8\)ZB[0-6]),"))ok=1;

# 12.2ZC
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-2])\)|12\.2)ZC[0-9]*,"))ok=1;

# 12.2ZD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZD[0-9]*,"))ok=1;

# 12.2ZE
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZE[0-9]*,"))ok=1;

# 12.2ZJ
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)ZJ[0-9]*|12\.2\(15\)ZJ[0-0]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
