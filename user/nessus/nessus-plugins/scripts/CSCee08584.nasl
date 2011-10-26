#
# (C) Tenable Network Security
#
#
#


if(description)
{
 script_id(16217);
 script_bugtraq_id(12307);
 script_version("$Revision: 1.4 $");
 if ( defined_func("script_xref") ) {
	script_xref(name:"OSVDB", value:"13084");
	script_xref(name:"IAVA", value:"2005-B-0002");
	}

 name["english"] = "CSCee08584";

 script_name(english:name["english"]);

 desc["english"] = "
The remote router contains a version of IOS which has flaw in its telephony
service.

If the remote router is configured for ITS, CME or SRST, then an attacker
may send malformed TCP queries to the remote host resulting in a reboot
of the router.

CISCO identifies this vulnerability as bug id CSCee08584

Solution : http://www.cisco.com/en/US/products/products_security_advisory09186a00803b3fff.shtml
Risk Factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2005 Tenable Network Security");

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
# 12.1YD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YD[0-9]*,"))ok=1;

# 12.1YE
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YE[0-9]*,"))ok=1;

# 12.1YI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YI[0-9]*,"))ok=1;

# 12.2B
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)B[0-9]*,"))ok=1;

# 12.2BC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BC[0-9]*,"))ok=1;

# 12.2CZ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)CZ[0-9]*,"))ok=1;

# 12.2JK
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)JK[0-9]*|12\.2\(15\)JK[0-1]),"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)T[0-9]*|12\.2\(15\)T([0-9]|1[0-2])),"))ok=1;

# 12.2XB
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XB[0-9]*,"))ok=1;

# 12.2XG
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XG[0-9]*,"))ok=1;

# 12.2XM
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XM[0-9]*,"))ok=1;

# 12.2XT
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XT[0-9]*,"))ok=1;

# 12.2XU
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XU[0-9]*,"))ok=1;

# 12.2XW
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XW[0-9]*,"))ok=1;

# 12.2XZ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XZ[0-9]*,"))ok=1;

# 12.2YA
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)YA[0-9]*|12\.2\(4\)YA[0-7]),"))ok=1;

# 12.2YB
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YB[0-9]*,"))ok=1;

# 12.2YC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YC[0-9]*,"))ok=1;

# 12.2YD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YD[0-9]*,"))ok=1;

# 12.2YF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YF[0-9]*,"))ok=1;

# 12.2YG
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YG[0-9]*,"))ok=1;

# 12.2YH
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YH[0-9]*,"))ok=1;

# 12.2YJ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YJ[0-9]*,"))ok=1;

# 12.2YL
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YL[0-9]*,"))ok=1;

# 12.2YM
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YM[0-9]*,"))ok=1;

# 12.2YN
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YN[0-9]*,"))ok=1;

# 12.2YQ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YQ[0-9]*,"))ok=1;

# 12.2YR
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YR[0-9]*,"))ok=1;

# 12.2YS
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YS[0-9]*,"))ok=1;

# 12.2ZK
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZK[0-9]*,"))ok=1;

# 12.2ZO
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZO[0-9]*,"))ok=1;

# 12.2ZP
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZP[0-9]*,"))ok=1;

# 12.3
if(egrep(string:os, pattern:"(12\.3\([0-8]\)|12\.3),"))ok=1;

# 12.3T
if(egrep(string:os, pattern:"((12\.3\([0-1]\)|12\.3)T[0-9]*|12\.3\(2\)T[0-6]),"))ok=1;

# 12.3XA
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)XA[0-9]*,"))ok=1;

# 12.3XB
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)XB[0-9]*,"))ok=1;

# 12.3XC
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)XC[0-9]*,"))ok=1;

# 12.3XD
if(egrep(string:os, pattern:"((12\.3\([0-3]\)|12\.3)XD[0-9]*|12\.3\(4\)XD[0-2]),"))ok=1;

# 12.3XE
if(egrep(string:os, pattern:"((12\.3\([0-1]\)|12\.3)XE[0-9]*|12\.3\(2\)XE[0-0]),"))ok=1;

# 12.3XF
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)XF[0-9]*,"))ok=1;

# 12.3XG
if(egrep(string:os, pattern:"((12\.3\([0-3]\)|12\.3)XG[0-9]*|12\.3\(4\)XG[0-1]),"))ok=1;

# 12.3XH
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)XH[0-9]*,"))ok=1;

# 12.3XI
if(egrep(string:os, pattern:"(12\.3\([0-6]\)|12\.3)XI[0-9]*,"))ok=1;

# 12.3XJ
if(egrep(string:os, pattern:"((12\.3\([0-6]\)|12\.3)XJ[0-9]*|12\.3\(7\)XJ[0-1]),"))ok=1;

# 12.3XK
if(egrep(string:os, pattern:"((12\.3\([0-3]\)|12\.3)XK[0-9]*|12\.3\(4\)XK[0-0]),"))ok=1;

# 12.3XL
if(egrep(string:os, pattern:"(12\.3\([0-6]\)|12\.3)XL[0-9]*,"))ok=1;

# 12.3XN
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)XN[0-9]*,"))ok=1;

# 12.3XQ
if(egrep(string:os, pattern:"((12\.3\([0-3]\)|12\.3)XQ[0-9]*|12\.3\(4\)XQ[0-0]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
