#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
#


if(description)
{
 script_id(11382);
 script_bugtraq_id(5114);
 script_cve_id("CVE-2002-1024");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-A-0013");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-b-0006");

 script_version("$Revision: 1.7 $");

 name["english"] = "CSCdv85279, CSCdw59394";

 script_name(english:name["english"]);

 desc["english"] = "

It is possible to make the remote CatOS crash
wehn sending malformed SSH packets.

This vulnerability is documented with the CISCO
bug ID CSCdv85279 and CSCdw59394

Solution : http://www.cisco.com/warp/public/707/SSH-scanning.shtml
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
# catalyst6.*
if(ereg(string:hardware, pattern:"^catalyst6.*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this CatOS ?
if(!egrep(pattern:".*Cisco Catalyst Operating System.*", string:os))exit(0);
# 6.3
if(egrep(string:os, pattern:"(6\.3\(([0-2][^0-9]|3.[0-5])\)|6\.3),"))ok=1;

# 7.1
if(egrep(string:os, pattern:"(7\.1\(([0-1][^0-9]|0.([0-9]|[1-8][0-9]|9[0-3]))\)|7\.1),"))ok=1;

# 7.2
if(egrep(string:os, pattern:"(7\.2\(([0-1][^0-9]|0.([0-9]|1[0-3]))\)|7\.2),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
