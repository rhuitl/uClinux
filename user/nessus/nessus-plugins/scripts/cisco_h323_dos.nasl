#
# (C) Tenable Network Security
#
#


if(description)
{
 script_id(12023);
 script_bugtraq_id(9406);

 script_version("$Revision: 1.2 $");

 name["english"] = "CISCO IOS H.323 Protocol Implementation Flaws";

 script_name(english:name["english"]);

 desc["english"] = "

The remote router contains a version of IOS which has multiple flaws when
dealing with packets using the H.323 protocol. These flaws range from
a denial of service to possible code execution.

An attacker may use this flaw to render this router inoperable or take
its control.

Solution : http://www.cisco.com/warp/public/707/cisco-sa-20040113-h323.shtml
Risk factor : High

*** As Nessus solely relied on the banner of the remote host
*** this might be a false positive
";
 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2004 Tenable Network Security");

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
# 11.3T
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3)T[0-9]*,"))ok=1;

# 12.0
if(egrep(string:os, pattern:"(12\.0\(([0-9]|[1-1][0-9]|2[0-7])\)|12\.0),"))ok=1;

# 12.0S
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-4])\)|12\.0)S[0-9]*|12\.0\(25\)S[0-0]),"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)ST[0-9]*,"))ok=1;

# 12.0T
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)T[0-9]*,"))ok=1;

# 12.0XC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XC[0-9]*,"))ok=1;

# 12.0XD
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XD[0-9]*,"))ok=1;

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

# 12.0XN
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XN[0-9]*,"))ok=1;

# 12.0XN
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XN[0-9]*,"))ok=1;

# 12.0XQ
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XQ[0-9]*,"))ok=1;

# 12.0XR
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XR[0-9]*,"))ok=1;

# 12.0XT
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XT[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\(([0-9]|[1-1][0-9]|2[0-1])\)|12\.1),"))ok=1;

# 12.1AA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)AA[0-9]*,"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"((12\.1\(([0-9]|1[0-9])\)|12\.1)E[0-9]*|12\.1\(20\)E[0-1]),"))ok=1;

# 12.1EC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)EC[0-9]*,"))ok=1;

# 12.1EZ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)EZ[0-9]*,"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)T[0-9]*|12\.1\(5\)T([0-9]|1[0-6])),"))ok=1;

# 12.1X
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)X[0-9]*,"))ok=1;

# 12.1XA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XA[0-9]*,"))ok=1;

# 12.1XB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XB[0-9]*,"))ok=1;

# 12.1XC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XC[0-9]*,"))ok=1;

# 12.1XD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XD[0-9]*,"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XG[0-9]*,"))ok=1;

# 12.1XH
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XH[0-9]*,"))ok=1;

# 12.1XI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XI[0-9]*,"))ok=1;

# 12.1XJ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XJ[0-9]*,"))ok=1;

# 12.1XL
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XL[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XM[0-9]*,"))ok=1;

# 12.1XP
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XP[0-9]*,"))ok=1;

# 12.1XQ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XQ[0-9]*,"))ok=1;

# 12.1XQ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XQ[0-9]*,"))ok=1;

# 12.1XR
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XR[0-9]*,"))ok=1;

# 12.1XT
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XT[0-9]*,"))ok=1;

# 12.1XU
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XU[0-9]*,"))ok=1;

# 12.1XV
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XV[0-9]*,"))ok=1;

# 12.1XW
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XW[0-9]*,"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YB[0-9]*,"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YC[0-9]*,"))ok=1;

# 12.1YD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YD[0-9]*,"))ok=1;

# 12.1YE
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YE[0-9]*,"))ok=1;

# 12.1YF
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YF[0-9]*,"))ok=1;

# 12.1YH
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YH[0-9]*,"))ok=1;

# 12.1YI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YI[0-9]*,"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-6])\)|12\.2),"))ok=1;

# 12.2B
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)B[0-9]*,"))ok=1;

# 12.2BW
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BW[0-9]*,"))ok=1;

# 12.2BX
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BX[0-9]*,"))ok=1;

# 12.2BZ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BZ[0-9]*,"))ok=1;

# 12.2DD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)DD[0-9]*,"))ok=1;

# 12.2DX
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)DX[0-9]*,"))ok=1;

# 12.2MC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)MC[0-9]*,"))ok=1;

# 12.2MX
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)MX[0-9]*,"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-7])\)|12\.2)S[0-9]*|12\.2\(18\)S[0-2]),"))ok=1;

# 12.2SX
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)SX[0-9]*,"))ok=1;

# 12.2SY
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-3])\)|12\.2)SY[0-9]*|12\.2\(14\)SY[0-2]),"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)T[0-9]*|12\.2\(15\)T[0-4]),"))ok=1;

# 12.2XA
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XA[0-9]*,"))ok=1;

# 12.2XB
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XB[0-9]*|12\.2\(2\)XB([0-9]|1[0-4])),"))ok=1;

# 12.2XC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XC[0-9]*,"))ok=1;

# 12.2XD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XD[0-9]*,"))ok=1;

# 12.2XG
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XG[0-9]*,"))ok=1;

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

# 12.2XM
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XM[0-9]*,"))ok=1;

# 12.2XQ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XQ[0-9]*,"))ok=1;

# 12.2XS
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XS[0-9]*,"))ok=1;

# 12.2XT
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XT[0-9]*,"))ok=1;

# 12.2XU
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XU[0-9]*,"))ok=1;

# 12.2XW
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XW[0-9]*,"))ok=1;

# 12.2YA
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)YA[0-9]*|12\.2\(4\)YA[0-6]),"))ok=1;

# 12.2YB
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YB[0-9]*,"))ok=1;

# 12.2YC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YC[0-9]*,"))ok=1;

# 12.2YD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YD[0-9]*,"))ok=1;

# 12.2YE
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YE[0-9]*,"))ok=1;

# 12.2YF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YF[0-9]*,"))ok=1;

# 12.2YH
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YH[0-9]*,"))ok=1;

# 12.2YJ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YJ[0-9]*,"))ok=1;

# 12.2YK
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YK[0-9]*,"))ok=1;

# 12.2YL
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YL[0-9]*,"))ok=1;

# 12.2YM
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YM[0-9]*,"))ok=1;

# 12.2YN
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YN[0-9]*,"))ok=1;

# 12.2YT
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YT[0-9]*,"))ok=1;

# 12.2YU
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YU[0-9]*,"))ok=1;

# 12.2YV
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YV[0-9]*,"))ok=1;

# 12.2YW
if(egrep(string:os, pattern:"((12\.2\([0-7]\)|12\.2)YW[0-9]*|12\.2\(8\)YW[0-2]),"))ok=1;

# 12.2YX
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YX[0-9]*,"))ok=1;

# 12.2YY
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YY[0-9]*,"))ok=1;

# 12.2YZ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YZ[0-9]*,"))ok=1;

# 12.2ZB
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZB[0-9]*,"))ok=1;

# 12.2ZC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZC[0-9]*,"))ok=1;

# 12.2ZD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZD[0-9]*,"))ok=1;

# 12.2ZE
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZE[0-9]*,"))ok=1;

# 12.2ZF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZF[0-9]*,"))ok=1;

# 12.2ZG
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZG[0-9]*,"))ok=1;

# 12.2ZH
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZH[0-9]*,"))ok=1;

# 12.2ZJ
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)ZJ[0-9]*|12\.2\(15\)ZJ[0-2]),"))ok=1;

# 12.2ZL
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)ZL[0-9]*|12\.2\(15\)ZL[0-0]),"))ok=1;

# 12.3T
if(egrep(string:os, pattern:"((12\.3\([0-3]\)|12\.3)T[0-9]*|12\.3\(4\)T[0-0]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
