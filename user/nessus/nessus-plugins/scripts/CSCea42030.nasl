#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
#


if(description)
{
 script_id(11547);
 script_cve_id("CVE-2003-0216");

 script_version("$Revision: 1.4 $");

 name["english"] = "CSCea42030";

 script_name(english:name["english"]);

 desc["english"] = "

The remote Catalyst is vulnerable to password bypass vulnerability. Basically,
an attacker who has a command line access may gain the 'enable' privileges
without having to know the right password, which would allow him to reconfigure
this host remotely.

This vulnerability is documented with the CISCO bug ID CSCde42030

Solution : http://www.cisco.com/warp/public/707/cisco-sa-20030424-catos.shtml
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
# 7.5
if(egrep(string:os, pattern:"(7\.5\([0-9]*\)|7\.5),"))ok=1;

# 7.6
if(egrep(string:os, pattern:"(7\.6\([0-0]\)|7\.6),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
