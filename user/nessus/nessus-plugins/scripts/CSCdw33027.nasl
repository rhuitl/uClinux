#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
#


if(description)
{
 script_id(11381);
 script_bugtraq_id(5114);
 script_cve_id("CVE-2002-1024");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-A-0013");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-b-0006");

 script_version("$Revision: 1.7 $");

 name["english"] = "CSCdw33027";

 script_name(english:name["english"]);

 desc["english"] = "

It is possible to make the remote IOS crash when sending
it malformed SSH packets.

Solution : See http://www.cisco.com/warp/public/707/SSH-scanning.shtml
Risk factor : High

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
# 12.0S
if(egrep(string:os, pattern:"((12\.0\(([0-9]|1[0-6])\)|12\.0)S[0-9]*|12\.0\(17\)S[0-3]),"))ok=1;

# 12.0SP
if(egrep(string:os, pattern:"((12\.0\(([0-9]|1[0-9])\)|12\.0)SP[0-9]*|12\.0\(20\)SP[0-1]),"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"((12\.0\(([0-9]|1[0-6])\)|12\.0)ST[0-9]*|12\.0\(17\)ST[0-4]),"))ok=1;

# 12.0XB
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XB[0-9]*,"))ok=1;

# 12.0XM
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XM[0-9]*,"))ok=1;

# 12.0XV
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XV[0-9]*,"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(12\.1\(([0-9][^0-9]|10.[0-4])\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EC
if(egrep(string:os, pattern:"(12\.1\(([0-9][^0-9]|10.[0-4])\)|12\.1)EC[0-9]*,"))ok=1;

# 12.1EX
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)EX[0-9]*,"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)T[0-9]*,"))ok=1;

# 12.1XB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XB[0-9]*,"))ok=1;

# 12.1XC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XC[0-9]*,"))ok=1;

# 12.1XF
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XF[0-9]*,"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XG[0-9]*,"))ok=1;

# 12.1XH
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XH[0-9]*,"))ok=1;

# 12.1X1
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)X1[0-9]*,"))ok=1;

# 12.1XJ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XJ[0-9]*,"))ok=1;

# 12.1XL
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XL[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XM[0-9]*|12\.1\(5\)XM[0-6]),"))ok=1;

# 12.1XP
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XP[0-9]*,"))ok=1;

# 12.1XQ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XQ[0-9]*,"))ok=1;

# 12.1XT
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XT[0-9]*,"))ok=1;

# 12.1XU
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XU[0-9]*,"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YB[0-9]*|12\.1\(5\)YB[0-5]),"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YC[0-9]*|12\.1\(5\)YC[0-2]),"))ok=1;

# 12.1YD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YD[0-9]*,"))ok=1;

# 12.1YE
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YE[0-9]*,"))ok=1;

# 12.1YF
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YF[0-9]*,"))ok=1;

# 12.1YI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YI[0-9]*,"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\([0-6]\)|12\.2),"))ok=1;

# 12.B
if(egrep(string:os, pattern:"((12\.\([0-3]\)|12\.)B[0-9]*|12\.\(4\)B[0-2]),"))ok=1;

# 12.2BC
if(egrep(string:os, pattern:"((12\.2\([0-7]\)|12\.2)BC[0-9]*|12\.2\(8\)BC[0-0]),"))ok=1;

# 12.2DA
if(egrep(string:os, pattern:"(12\.2\([0-6]\)|12\.2)DA[0-9]*,"))ok=1;

# 12.2DD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)DD[0-9]*,"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"(12\.2\(([0-6][^0-9]|7.[0-3])\)|12\.2)S[0-9]*,"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"(12\.2\([0-7]\)|12\.2)T[0-9]*,"))ok=1;

# 12.2XA
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XA[0-9]*,"))ok=1;

# 12.2XB
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XB[0-9]*|12\.2\(2\)XB[0-3]),"))ok=1;

# 12.2XD
if(egrep(string:os, pattern:"((12\.2\([0-0]\)|12\.2)XD[0-9]*|12\.2\(1\)XD[0-3]),"))ok=1;

# 12.2XE
if(egrep(string:os, pattern:"((12\.2\([0-0]\)|12\.2)XE[0-9]*|12\.2\(1\)XE[0-2]),"))ok=1;

# 12.2XF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XF[0-9]*,"))ok=1;

# 12.2XG
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XG[0-9]*,"))ok=1;

# 12.2XH
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XH[0-9]*|12\.2\(2\)XH[0-2]),"))ok=1;

# 12.2XI
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XI[0-9]*|12\.2\(2\)XI[0-1]),"))ok=1;

# 12.2XJ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XJ[0-9]*,"))ok=1;

# 12.2XK
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XK[0-9]*|12\.2\(2\)XK[0-2]),"))ok=1;

# 12.2XL
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)XL[0-9]*|12\.2\(4\)XL[0-4]),"))ok=1;

# 12.2XM
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)XM[0-9]*|12\.2\(4\)XM[0-3]),"))ok=1;

# 12.2XN
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XN[0-9]*,"))ok=1;

# 12.2XQ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XQ[0-9]*,"))ok=1;

# 12.2XR
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XR[0-9]*,"))ok=1;

# 12.2XS
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XS[0-9]*,"))ok=1;

# 12.2XT
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XT[0-9]*,"))ok=1;

# 12.2XW
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XW[0-9]*,"))ok=1;

# 12.2XW
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XW[0-9]*,"))ok=1;

# 12.2YA
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)YA[0-9]*|12\.2\(4\)YA[0-1]),"))ok=1;

# 12.2YB
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YB[0-9]*,"))ok=1;

# 12.2YC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YC[0-9]*,"))ok=1;

# 12.2YD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YD[0-9]*,"))ok=1;

# 12.2YF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YF[0-9]*,"))ok=1;

# 12.2YG
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)YG[0-9]*,"))ok=1;

# 12.2YH
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)YH[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
