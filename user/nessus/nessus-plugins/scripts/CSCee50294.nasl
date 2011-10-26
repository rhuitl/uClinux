#
# (C) Tenable Network Security
#
#
#


if(description)
{
 script_id(15782);
 script_bugtraq_id(11649);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-b-0014");

 script_version("$Revision: 1.3 $");

 name["english"] = "CSCee50294";

 script_name(english:name["english"]);

 desc["english"] = "

The remote router contains a version of IOS which has flaw in the DHCP
service/relay service which may let an attacker to disable DHCP serving
and or relaying on the remote router.

CISCO identifies this vulnerability as bug id CSCee50294.

Solution : http://www.cisco.com/warp/public/707/cisco-sa-20041110-dhcp.shtml
Risk Factor : High

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
# 12.2EW
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-7])\)|12\.2)EW[0-9]*|12\.2\(18\)EW[0-1]),"))ok=1;

# 12.2EWA
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-9])\)|12\.2)EWA[0-9]*,"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-7])\)|12\.2)S[0-9]*|12\.2\(18\)S[0-5]),"))ok=1;

# 12.2SE
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-9])\)|12\.2)SE[0-9]*|12\.2\(20\)SE[0-2]),"))ok=1;

# 12.2SV
if(egrep(string:os, pattern:"(12\.2\(([0-9]|[1-1][0-9]|2[0-3])\)|12\.2)SV[0-9]*,"))ok=1;

# 12.2SW
if(egrep(string:os, pattern:"(12\.2\(([0-9]|[1-1][0-9]|2[0-4])\)|12\.2)SW[0-9]*,"))ok=1;

# 12.2SZ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)SZ[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
