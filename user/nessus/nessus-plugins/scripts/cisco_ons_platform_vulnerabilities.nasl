#
# (C) Tenable Network Security
#


if(description)
{
 script_id(16202);
 script_bugtraq_id(9699, 6084, 6083, 6082, 6081, 6078, 6076, 6073, 5058);
 script_version("$Revision: 1.2 $");

 name["english"] = "CISCO ONS Platform Vulnerabilities";

 script_name(english:name["english"]);

 desc["english"] = "

The remote Cisco ONS platform is vulnerable to various denial of
service and authentication vulnerabilities :

- The TFTP server allows unauthenticated access to TFTP GET and PUT
commands. An attacker may exploit this flaw to upload or retrieve the 
system files of the remote ONS platform ;

- A denial of service attack may occur through the network management
port of the remote device (1080/tcp) ;

- Superuser accounts can not be disabled over telnet ;


Solution : http://www.cisco.com/warp/public/707/cisco-sa-20040219-ONS.shtml
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
 if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 2) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15454.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15454.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 5 ) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15600.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15600.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) <= 1 ) security_hole(port);
}
