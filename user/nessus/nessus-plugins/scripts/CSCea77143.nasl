#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
#


if(description)
{
 script_id(11594);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0011");
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0258","CVE-2003-0259","CVE-2003-0260");
 name["english"] = "CSCdea77143, CSCdz15393, CSCdt84906";
 

 script_name(english:name["english"]);

 desc["english"] = "

The remote Cisco VPN 3000 concentrator is vulnerable to various flaws
which may allow an attacker to use this device
to break into a VPN, disable the remote device by sending
a malformed SSH initialization packet or disable the
remote device by sending a flood of malformed ICMP packets.

This vulnerability is documented with the CISCO
bugs ID CSCdea77143, CSCdz15393 and CSCdt84906

Solution : http://www.cisco.com/warp/public/707/cisco-sa-20030507-vpn3k.shtml
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



# Check for the required hardware...
#----------------------------------------------------------------
# catalyst.*
if(ereg(string:hardware, pattern:"^catalyst.*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this CatOS ?

if(!egrep(pattern:".*Cisco Catalyst Operating System.*", string:os))exit(0);
# 3.0, 3.1 and 3.5 are vulnerable
if(egrep(string:os, pattern:"3\.[015].*,"))ok=1;


# 3.6.x fixed in 3.6.7
if(egrep(string:os, pattern:"3\.6\.[0-6][^0-9].*,"))ok=1;
if(egrep(string:os, pattern:"3\.6\.7[A-E].*,"))ok=1;


# 4.x -> fixed in 4.0.1
if(egrep(string:os, pattern:"4\.0(\.0)?.*,"))ok=1;



if(ok)security_hole(port:161, proto:"udp");
