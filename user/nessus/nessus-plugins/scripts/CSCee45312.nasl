#
# (C) Tenable Network Security
#


if(description)
{
 script_id(20933);
 script_bugtraq_id(14092);
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-B-0015");

 script_version("$Revision: 1.1 $");


 name["english"] = "Cisco IOS AAA RADIUS Authentication Bypass Vulnerability";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote Cisco IOS RADIUS server is prone to a remote authentication
bypass vulnerability.

Description :

The remote host is a CISCO router containing a version of IOS which 
contains a faulty RADIUS implementation which may lead to an 
authentication bypass vulnerability.

An attacker may exploit this problem to gain unauthorized access
to the service.

Solution :

http://www.cisco.com/warp/public/707/cisco-sa-20050629-aaa.shtml

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2006 Tenable Network Security");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}


include('cisco_func.inc');

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);
version = extract_version(os);
if ( ! version ) exit(0);



# 12.2

if ( deprecated_version(version, "12.2B", "12.2BC", "12.2BW", "12.2BX", "12.2BY", "12.2BZ", "12.2CX", "12.2CY", "12.2CZ", "12.2EW", "12.2EZ", "12.2JA", "12.2MB", "12.2MC", "12.2MX", "12.2T", "12.2XB", "12.2XC", "12.2XD", "12.2XE", "12.2XF", "12.2XG", "12.2XH", "12.2XI", "12.2XJ", "12.2XK", "12.2XL", "12.2XM", "12.2XQ", "12.2XR", "12.2XT", "12.2XW", "12.2YA", "12.2YB", "12.2YC", "12.2YD", "12.2YF", "12.2YG", "12.2YH", "12.2YJ", "12.2YM", "12.2YN", "12.2YP", "12.2YQ", "12.2YR", "12.2YT", "12.2YU", "12.2YV", "12.2YW", "12.2YY", "12.ZB", "12.2ZC", "12.2ZD", "12.2ZE", "12.2ZF", "12.2ZG", "12.2ZH", "12.2ZJ", "12.2ZL", "12.2ZN", "12.2ZO", "12.2ZP") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)EWA2"),
		   newest:"12.2(25)EWA2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)EY2"),
		   newest:"12.2(25)EY2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)SXD5"),
		   newest:"12.2(18)SXD5") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)SXE2"),
		   newest:"12.2(18)SXE2") ) vuln ++;

#
# 12.3
#

if ( deprecated_version(version, "12.3B", "12.3BW", "12.3XA", "12.3XB", "12.3XC", "12.3XD", "12.3XE", "12.3XF", "12.3XG", "12.3XH", "12.3XJ", "12.3XK", "12.3XN", "12.3XQ", "12.3XR", "12.3XS", "12.3XT", "12.3XU", "12.3XW", "12.3XX", "12.3YA", "12.3YB") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(10)"),
		   newest:"12.3(10)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(13)BC"),
		   newest:"12.3(13)BC") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)JA"),
		   newest:"12.3(7)JA") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)T4", "12.3(7)T11"),
		   newest:"12.3(7)T11") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)XI6"),
		   newest:"12.3(7)XI6") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)XL"),
		   newest:"12.3(11)XL") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)XY5"),
		   newest:"12.3(8)XY5") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YD"),
		   newest:"12.3(8)YD") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YF"),
		   newest:"12.3(11)YF") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YG"),
		   newest:"12.3(8)YG")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YH"),
		   newest:"12.3(8)YH")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YI"),
		   newest:"12.3(8)YI")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YJ"),
		   newest:"12.3(11)YJ")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YK"),
		   newest:"12.3(11)YK")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YL"),
		   newest:"12.3(11)YL")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YN"),
		   newest:"12.3(11)YN")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YR"),
		   newest:"12.3(11)YR")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YS"),
		   newest:"12.3(11)YS")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YQ"),
		   newest:"12.3(14)YQ")) vuln ++;

# 12.4

if ( check_release(version:version, 
		   patched:make_list("12.4(1)"),
		   newest:"12.4(1)") ) vuln ++;


if ( vuln == 1 ) security_warning(port:161, proto:"udp");
else if ( vuln > 1 )  display("Problem in script $Id: CSCee45312.nasl,v 1.1 2006/02/17 16:55:05 renaud Exp $\n");


