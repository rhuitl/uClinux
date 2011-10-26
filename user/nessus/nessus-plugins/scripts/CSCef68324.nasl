#
# (C) Tenable Network Security
#


if(description)
{
 script_id(19771);
 script_bugtraq_id(14414);
 script_cve_id("CVE-2005-2451");
 script_version("$Revision: 1.2 $");

 name["english"] = "Cisco IOS IPv6 Processing Arbitrary Code Execution Vulnerability";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote router contains a vulnerability which may allow an attacker to
execute arbitary code on it.

Description :

The remote version of IOS is vulnerable to a code execution vulnerability when
processing malformed IPv6 packets. 

To exploit this flaw, an attacker would need to ability to send a malformed
packet from a local segment and may exploit this issue to cause the remote
device to reload repeatedly or to execute arbitrary code in the remote IOS.

See also :

http://www.cisco.com/warp/public/707/cisco-sa-20050729-ipv6.shtml

Solution : 

Cisco has made a set of patches available which are listed at the address above.

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2005 Tenable Network Security");

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



# 12.0

if ( deprecated_version(version, "12.0SL", "12.0ST", "12.0SY") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.0(26)S6", "12.0(27)S5", "12.0(28)S3", "12.0(30)S2"),
		   newest:"12.0(30)S2") ) vuln ++;

# 12.1

if ( deprecated_version(version, "12.1XU", "12.1XV", "12.1YB", "12.1YC", "12.1YD", "12.1YE", "12.1YF", "12.1YH", "12.1YI") ) vuln ++;

# 12.2

if ( deprecated_version(version, "12.2B","12.2BW", "12.2BY", "12.2BX", "12.2BZ", "12.2CX", "12.2CY", "12.2DD", "12.2DX", "12.2JA", "12.2MX", "12.2SO", "12.2SU", "12.2SX", "12.2SXA", "12.2SY", "12.2SZ", "12.2XA", "12.2XB", "12.2CX", "12.2XF", "12.2XG", "12.2XH", "12.2XI", "12.2XJ", "12.2XK", "12.2XL", "12.2XM", "12.2XN", "12.2XQ", "12.2XR", "12.2XT", "12.2XU", "12.2XW", "12.2XZ", "12.2YB", "12.2YC", "12.2YD", "12.2YE", "12.2YF", "12.2YG", "12.2YH", "12.2YJ", "12.2YK", "12.2YL", "12.2YM", "12.2YN", "12.2YO", "12.2YP", "12.2YQ", "12.2YR", "12.2YT", "12.2YU", "12.2YV", "12.2YW", "12.2YX", "12.2YY", "12.2YZ", "12.2ZA", "12.2ZB", "12.2ZC", "12.2ZE", "12.2ZF", "12.2ZH", "12.2ZJ", "12.2ZL", "12.2ZN", "12.2ZO", "12.2ZP") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(15)BC2h"),
		   newest:"12.2(15)BC2h") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(20)EU1"),
		   newest:"12.2(20)EU1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(20)EW2"),
		   newest:"12.2(20)EW2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(20)EWA2", "12.2(25)EWA1"),
		   newest:"12.2(25)EW1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(25)EZ1"),
		   newest:"12.2(25)EZ1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(15)JK4"),
		   newest:"12.2(15)JK4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(4)MB13b"),
		   newest:"12.2(4)MB13b") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(15)MC2c"),
		   newest:"12.2(15)MC2c") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(14)S14", "12.2(18)S9", "12.2(20)S8", "12.2(25)S4"),
		   newest:"12.2(25)S4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(25)SEB3"),
		   newest:"12.2(25)SEB3") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(25)SEC1"),
		   newest:"12.2(25)SEC1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(18)SV3", "12.2(22)SV1", "12.2(23)SV1", "12.2(24)SV1", "12.2(25)SV2"),
		   newest:"12.2(25)SV2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(25)SW3a"),
		   newest:"12.2(25)SW3a") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(17d)SXB8"),
		   newest:"12.2(17d)SXB8") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(18)SXD4"),
		   newest:"12.2(18)SXD4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(18)SXE1"),
		   newest:"12.2(18)SXE1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(13)T16", "12.2(15)T16"),
		   newest:"12.2(15)T16") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(4)YA10"),
		   newest:"12.2(4)YA10") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(13)ZD3"),
		   newest:"12.2(13)ZD3") ) vuln ++;

# 12.3

if ( deprecated_version(version, "12.3BW", "12.3XD", "12.3XF", "12.3XH", "12.3XJ", "12.3XL", "12.3XM", "12.3XS", "12.3XT", "12.3XU", "12.3XW", "12.3XX", "12.3YD", "12.3YK") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(3h)", "12.3(5e)", "12.3(6e)", "12.3(9d)", "12.3(10d)", "12.3(12b)", "12.3(13a)", "12.3(15)"),
		   newest:"12.3(15)") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(3h)", "12.3(5e)", "12.3(6e)", "12.3(9d)", "12.3(10d)", "12.3(12b)", "12.3(13a)", "12.3(15)"),
		   newest:"12.3(15)") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(5a)B5"),
		   newest:"12.3(5a)B5") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(9a)BC6"),
		   newest:"12.3(9a)BC6") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(4)JA"),
		   newest:"12.3(4)JA") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(2)JK"),
		   newest:"12.3(2)JK") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(7)T9", "12.3(8)T8", "12.3(11)T5", "12.3(14)T2"),
		   newest:"12.3(14)T2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(2)XA4"),
		   newest:"12.3(2)XA4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(2)XC3"),
		   newest:"12.3(2)XC3") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(2)XE3"),
		   newest:"12.3(2)XE3") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(4)XG4"),
		   newest:"12.3(4)XG4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(4)XI4"),
		   newest:"12.3(4)XI4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(4)XK3"),
		   newest:"12.3(4)XK3") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(4)XQ1"),
		   newest:"12.3(4)XQ1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(7)XR4"),
		   newest:"12.3(7)XR4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(8)XY6"),
		   newest:"12.3(8)XY6") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(8)YA1"),
		   newest:"12.3(8)YA1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(11)YF3"),
		   newest:"12.3(11)YF3") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(8)YG2"),
		   newest:"12.3(8)YG2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(8)YI1"),
		   newest:"12.3(8)YI1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(11)YJ"),
		   newest:"12.3(11)YJ") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YQ1"),
		   newest:"12.3(14)YQ1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(11)YS"),
		   newest:"12.3(11)YS") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YT"),
		   newest:"12.3(14)YT") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YU"),
		   newest:"12.3(14)YU") ) vuln ++;

# 12.4
if ( check_release(version:version,
		   patched:make_list("12.4(1)"),
		   newest:"12.4(1)") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(2)MR"),
		   newest:"12.4(2)MR") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(2)T"),
		   newest:"12.4(2)T") ) vuln ++;

if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 )  display("Problem in script $Id: CSCef68324.nasl,v 1.2 2005/10/20 21:15:52 theall Exp $\n");


