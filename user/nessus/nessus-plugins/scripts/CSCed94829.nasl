#
# (C) Tenable Network Security
#


if(description)
{
 script_id(20807);
 script_bugtraq_id(15401);
 script_version("$Revision: 1.1 $");

 name["english"] = "IOS IPSec IKE Traffic Denial of Service Vulnerability"; 

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote router can be crashed remotely.

Description :

The remote host is a CISCO router containing a version of IOS which is
vulnerable to a denial of service vulnerability.

An attacker may exploit this flaw to crash the remote device by sending a 
malformed IKE packet to the remote device.

Solution :

http://www.cisco.com/warp/public/707/cisco-sa-20051114-ipsec.shtml

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:N/A:C/I:N/B:A)";


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


if ( check_release(version:version, 
		   patched:make_list("12.2(18)SXD7"),
		   newest:"12.2(18)SXD7") ) vuln ++;


#
# 12.3
#

if ( deprecated_version(version, "12.3TPC", "12.3XD", "12.3XE", "12.3XF", "12.3XG", "12.3XH", "12.3XI", "12.3XJ", "12.3XK", "12.3XM", "12.3XQ", "12.3XR", "12.3XS", "12.3XU", "12.3XW", "12.3XX", "12.3YA", "12.3YD", "12.3YF", "12.3YG", "12.3YH", "12.3YI", "12.3YJ", "12.3YK", "12.3YS", "12.3YT", "12.3YU", "12.3YX") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.3(11)T9", "12.3(14)T5"),
		   newest:"12.3(14)T5") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YM4"),
		   newest:"12.3(14)YM4") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YQ4"),
		   newest:"12.3(14)YQ4") ) vuln ++;



# 12.4
if ( deprecated_version(version, "12.3XA")) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(1c)", "12.4(3b)"),
		   newest:"12.4(3b)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)T2"),
		   newest:"12.4(4)T2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)XB"),
		   newest:"12.4(2)XB") ) vuln ++;


if ( vuln == 1 ) security_warning(port:161, proto:"udp");
else if ( vuln > 1 )  display("Problem in script $Id: CSCed94829.nasl,v 1.1 2006/01/25 18:02:07 renaud Exp $\n");


