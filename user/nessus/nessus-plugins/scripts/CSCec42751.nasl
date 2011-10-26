#
# (C) Tenable Network Security
#
#
#


if(description)
{
 script_id(12270);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-a-0011");
 script_bugtraq_id(10504);
 script_version("$Revision: 1.3 $");

 name["english"] = "CSCec42751, CSCed45576 and CSCed48590";
 script_name(english:name["english"]);

 desc["english"] = "
The remote switch is vulnerable to various flaws which may allow an
attacker to disable this device remotely by doing a TCP-ACK denial
of service attack.

This vulnerability is documented with the CISCO bugs ID CSCec42751,
CSCed45576 and CSCed48590

Solution : http://www.cisco.com/warp/public/707/cisco-sa-20040609-catos.shtml
Risk factor : High";
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
# 8.3
if(egrep(string:os, pattern:"(8\.3\([0-1]\)|8\.3),"))ok=1;

# 8.2
if(egrep(string:os, pattern:"(8\.2\([0-1]\)|8\.2),"))ok=1;

# 8.1
if(egrep(string:os, pattern:"(8\.1\([0-9]*\)|8\.1),"))ok=1;

# 8.0
if(egrep(string:os, pattern:"(8\.0\([0-9]*\)|8\.0),"))ok=1;

# 7.6
if(egrep(string:os, pattern:"(7\.6\([0-5]\)|7\.6),"))ok=1;

# 7.5
if(egrep(string:os, pattern:"(7\.5\([0-9]*\)|7\.5),"))ok=1;

# 7.4
if(egrep(string:os, pattern:"(7\.4\([0-9]*\)|7\.4),"))ok=1;

# 7.3
if(egrep(string:os, pattern:"(7\.3\([0-9]*\)|7\.3),"))ok=1;

# 7.2
if(egrep(string:os, pattern:"(7\.2\([0-9]*\)|7\.2),"))ok=1;

# 7.1
if(egrep(string:os, pattern:"(7\.1\([0-9]*\)|7\.1),"))ok=1;

# 7.0
if(egrep(string:os, pattern:"(7\.0\([0-9]*\)|7\.0),"))ok=1;

# 6.4
if(egrep(string:os, pattern:"(6\.4\([0-8]\)|6\.4),"))ok=1;

# 6.3
if(egrep(string:os, pattern:"(6\.3\([0-9]*\)|6\.3),"))ok=1;

# 6.2
if(egrep(string:os, pattern:"(6\.2\([0-9]*\)|6\.2),"))ok=1;

# 6.1
if(egrep(string:os, pattern:"(6\.1\([0-9]*\)|6\.1),"))ok=1;

# 6.0
if(egrep(string:os, pattern:"(6\.0\([0-9]*\)|6\.0),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\(([0-9]|1[0-9])\)|5\.5),"))ok=1;

# 5.4
if(egrep(string:os, pattern:"(5\.4\([0-9]*\)|5\.4),"))ok=1;

# 5.3
if(egrep(string:os, pattern:"(5\.3\([0-9]*\)|5\.3),"))ok=1;

# 5.2
if(egrep(string:os, pattern:"(5\.2\([0-9]*\)|5\.2),"))ok=1;

# 5.1
if(egrep(string:os, pattern:"(5\.1\([0-9]*\)|5\.1),"))ok=1;

# 5.0
if(egrep(string:os, pattern:"(5\.0\([0-9]*\)|5\.0),"))ok=1;

# Older than that
if(egrep(string:os, pattern:"([1-4]\.0\([0-9]*\)|[1-4]\.0),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
