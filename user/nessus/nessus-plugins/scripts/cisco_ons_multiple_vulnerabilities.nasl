#
# (C) Tenable Network Security
#


if(description)
{
 script_id(16201);
 script_bugtraq_id(10768);
 script_version("$Revision: 1.1 $");

 name["english"] = "CISCO ONS Multiple Vulnerabilities";

 script_name(english:name["english"]);

 desc["english"] = "

The remote Cisco ONS platform is vulnerable to various vulnerabilities 
which may allow an attacker to cause a denial of service in the remote
control cards or to bypass authentication on the remote device.


Solution : http://www.cisco.com/warp/public/707/cisco-sa-20040721-ons.shtml
Risk Factor : High";
 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2005 Tenable Network Security");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/sysDesc");
 exit(0);
}


sysDesc = get_kb_item("SNMP/sysDesc"); 
if ( ! sysDesc ) exit(0);

if ("Cisco ONS" >!< sysDesc ) exit(0);

if ( egrep(pattern:"Cisco ONS 15327.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15327.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) <= 3 ) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 3) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 6 && int(int_version[3]) <= 1) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15454.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15454.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) <= 3 ) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 3) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 5 ) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 6 && int(int_version[3]) <= 1) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15600.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15600.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) <= 1 ) security_hole(port);
}
