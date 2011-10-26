#
# (C) Tenable Network Security
#
# See the Nessus Script License for details
#
#


if(description)
{
 script_id(11632);
 script_cve_id("CVE-2003-0305");

 script_version("$Revision: 1.5 $");

 name["english"] = "CSCdx17916, CSCdx61997";

 script_name(english:name["english"]);

 desc["english"] = "

It is possible to crash the remote router by sending malformed
Response Time Responder (RTR) packets. 
For this flaw to be exploitable, the router needs
to have RTR responder enabled.

This bug is referenced as CISCO bug id CSCdx17916 and CSCdx61997

Solution : See http://www.cisco.com/warp/public/707/cisco-sa-20030515-saa.shtml
Risk factor : High

*** As Nessus solely relied on the banner of the remote host
*** this might be a false positive
";
 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003 Tenable Network Security");

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
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-0])\)|12\.0)S[0-9]*|12\.0\(21\)S[0-2]),"))ok=1;

# 12.0SC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SC[0-9]*,"))ok=1;

# 12.0SL
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SL[0-9]*,"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-0])\)|12\.0)ST[0-9]*|12\.0\(21\)ST[0-1]),"))ok=1;

# 12.0WC
if(egrep(string:os, pattern:"(12\.0\([0-4]\)|12\.0)WC[0-9]*,"))ok=1;

# 12.0SX
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SX[0-9]*,"))ok=1;

# 12.0SY
if(egrep(string:os, pattern:"(12\.0\(([0-9]|[1-1][0-9]|2[0-1])\)|12\.0)SY[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-7])\)|12\.1),"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-2])\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)EA[0-9]*,"))ok=1;

# 12.1EW
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-0])\)|12\.1)EW[0-9]*,"))ok=1;

# 12.1EX
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-0])\)|12\.1)EX[0-9]*,"))ok=1;

# 12.1XF
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XF[0-9]*,"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XG[0-9]*,"))ok=1;

# 12.1YG
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YG[0-9]*,"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YC[0-9]*,"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\([0-9]\)|12\.2),"))ok=1;

# 12.2BC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BC[0-9]*,"))ok=1;

# 12.2BY
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BY[0-9]*,"))ok=1;

# 12.2BZ
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-4])\)|12\.2)BZ[0-9]*,"))ok=1;

# 12.2DA
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-1])\)|12\.2)DA[0-9]*,"))ok=1;

# 12.2MB
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)MB[0-9]*|12\.2\(4\)MB[0-4]),"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-1])\)|12\.2)S[0-9]*,"))ok=1;

# 12.2XC
if(egrep(string:os, pattern:"((12\.2\([0-0]\)|12\.2)XC[0-9]*|12\.2\(1\)XC[0-4]),"))ok=1;

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
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XK[0-9]*|12\.2\(2\)XK[0-2]),"))ok=1;

# 12.2XL
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)XL[0-9]*|12\.2\(4\)XL[0-4]),"))ok=1;

# 12.2XM
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XM[0-9]*,"))ok=1;

# 12.2YA
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)YA[0-9]*|12\.2\(4\)YA[0-2]),"))ok=1;

# 12.2YB
if(egrep(string:os, pattern:"(12\.2\([0-7]\)|12\.2)YB[0-9]*,"))ok=1;

# 12.2YC
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)YC[0-9]*|12\.2\(4\)YC[0-3]),"))ok=1;

# 12.2YF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YF[0-9]*,"))ok=1;

# 12.2YG
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)YG[0-9]*,"))ok=1;

# 12.2YH
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)YH[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
