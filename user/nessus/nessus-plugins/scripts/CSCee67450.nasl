#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17635);
 script_bugtraq_id(12370);
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-B-0003");

 script_version("$Revision: 1.2 $");

 name["english"] = "Cisco IOS BGP Processing Remote Denail of Service";

 script_name(english:name["english"]);

 desc["english"] = "
The remote version of IOS is vulnerable to a denial of service vulnerability 
when processing malformed BGP packets.

If IPv6 is enabled, an attacket may exploit this flaw to prevent the router 
from working properly.

Solution : http://www.cisco.com/warp/public/707/cisco-sa-20050126-bgp.shtml
Risk Factor : High";
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

# 12.0 Deprecated
if ( deprecated_version(version, "12.0DA", "12.0DB", "12.0DC", "12.0SC", "12.0SP", "12.0ST", "12.0SX", "12.0SY", "12.0SZ", "12.0WC", "12.0WT", "12.0WX", "12.0XA", "12.0XB", "12.0XC", "12.0XD", "12.0XE", "12.0XF", "12.0XG", "12.0XH", "12.0XI", "12.0XJ", "12.0XK", "12.0XL", "12.0XM", "12.0XN", "12.0XP", "12.0XQ", "12.0XR", "12.0XS", "12.0XT", "12.0XU", "12.0XV") ) vuln ++;

# 12.0
if ( check_release(version:version,
		   patched:make_list("12.0(28b)"),
		   newest:"12.0(28b)") ) vuln ++;

# 12.0S
if ( check_release(version:version,
		   patched:make_list("12.0(25)S5", "12.0(26)S2d", "12.0(26)S5", "12.0(27)S2d", "12.0(27)S4", "12.0(28)S1", "12.0(29)S"),
		   newest:"12.0(29)S") ) vuln ++;

# 12.0SV
if ( check_release(version:version,
		   patched:make_list("12.0(27)SV4"),
		   newest:"12.0(27)SV4") ) vuln ++;
# 12.0W
if ( check_release(version:version,
		   patched:make_list("12.0(28)W5"),
		   newest:"12.0(28)W5") ) vuln ++;


# 12.1
if ( deprecated_version(version, "12.1AA", "12.1AY", "12.1AZ", "12.1DA", "12.1DB", "12.1DC", "12.1EC", "12.1EO", "12.1EV", "12.1EW", "12.1EX", "12.1EY", "12.1IT", "12.1XA", "12.1XB", "12.1XC", "12.1XD", "12.1XD", "12.1XE", "12.1XF", "12.1XG", "12.1XH", "12.1XI", "12.1XJ", "12.1XL", "12.1XM", "12.1XP", "12.1XQ", "12.1XR", "12.1XT", "12.1XU", "12.1XV", "12.1YA", "12.1YB", "12.1YC", "12.1YD", "12.1YE", "12.1YF", "12.1YH", "12.1YI", "12.1YJ") ) vuln ++;


# 12.1
if ( check_release(version:version,
		   patched:make_list("12.1(26)"),
		   newest:"12.1(26)") ) vuln ++;

# 12.1AX
if ( check_release(version:version,
		   patched:make_list("12.1(14)AX3"),
		   newest:"12.1(14)AX3") ) vuln ++;
# 12.1E
if ( check_release(version:version,
		   patched:make_list("12.1(23)E2", "12.1(22)E3", "12.1(26)E"),
		   newest:"12.1(26)E") ) vuln ++;
# 12.1EA
if ( check_release(version:version,
		   patched:make_list("12.1(22)EA2"),
		   newest:"12.1(22)EA2") ) vuln ++;


# 12.2
if ( deprecated_version(version, "12.2B", "12.2BC", "12.2BW", "12.2BX", "12.2BY", "12.2BZ", "12.2CZ", "12.2DA", "12.2DD", "12.2DX", "12.2MB", "12.2MC", "12.2MX", "12.2SZ", "12.2SXA", "12.2SY", "12.2XA", "12.2XB", "12.2XC", "12.2XD", "12.2XE", "12.2XF", "12.2XG", "12.2XH", "12.2XI", "12.2XJ", "12.2XK", "12.2XL", "12.2XM", "12.2XN", "12.2XQ", "12.2XS", "12.2XT", "12.2XU", "12.2XW", "12.2XZ", "12.2YB", "12.2YC", "12.2YE", "12.2YF", "12.2YG", "12.2YH", "12.2YJ", "12.2YK", "12.2YL", "12.2YM", "12.2YN", "12.2YP", "12.2YQ", "12.2YT", "12.2YU", "12.2YV", "12.2YW", "12.2YX", "12.2YY", "12.2YZ", "12.2ZA", "12.2ZB", "12.2ZC", "12.2ZD", "12.2ZE", "12.2ZF", "12.2ZG", "12.2ZH", "12.2ZI", "12.2ZJ", "12.2ZK", "12.2ZL", "12.2ZN", "12.2ZO", "12/2ZP")) vuln ++;


# 12.2
if ( check_release(version:version,
		   patched:make_list("12.2(27)"),
		   newest:"12.2(27)") ) vuln ++;

# 12.2EW
if ( check_release(version:version,
		   patched:make_list("12.2(18)EW2", "12.2(25)EW"),
		   newest:"12.2(25)EW") ) vuln ++;

# 12.2JK
if ( check_release(version:version,
		   patched:make_list("12.2(15)JK2"),
		   newest:"12.2(15)JK2") ) vuln ++;
# 12.2S
if ( check_release(version:version,
		   patched:make_list("12.2(14)S13", "12.2S(18)S8", "12.2(20)S7", "12.2(25)S"),
		   newest:"12.2(25)S") ) vuln ++;

# 12.2SE
if ( check_release(version:version,
		   patched:make_list("12.2(20)SE3"),
		   newest:"12.2(20)SE3") ) vuln ++;
# 12.2SU
if ( check_release(version:version,
		   patched:make_list("12.2(14)SU2"),
		   newest:"12.2(14)SU2") ) vuln ++;
# 12.2SW
if ( check_release(version:version,
		   patched:make_list("12.2(25)SW"),
		   newest:"12.2(14)SU2") ) vuln ++;
# 12.2SXB
if ( check_release(version:version,
		   patched:make_list("12.2(17d)SXB5"),
		   newest:"12.2(14)SU2") ) vuln ++;
# 12.2SXD
if ( check_release(version:version,
		   patched:make_list("12.2(18)SXD2"),
		   newest:"12.2(18)SXD2") ) vuln ++;
# 12.2T
if ( check_release(version:version,
		   patched:make_list("12.2(15)T15"),
		   newest:"12.2(15)T15") ) vuln ++;
# 12.2YA
if ( check_release(version:version,
		   patched:make_list("12.2(4)YA8"),
		   newest:"12.2(4)YA8") ) vuln ++;
# 12.2ZK
if ( check_release(version:version,
		   patched:make_list("12.2(15)ZK6"),
		   newest:"12.2(15)ZK6") ) vuln ++;

# 12.3

if ( deprecated_version(version, "12.3BW", "12.3XA", "12.3XB", "12.3XF", "12.3XG", "12.3XH", "12.3XJ", "12.3XK", "12.3XL", "12.3XN", "12.3XR", "12.3YC", "12.3YD", "12.3YF", "12.3YH", "12.3YJ", "12.3YL") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(6d)", "12.3(9c)", "12.3(10a)", "12.3(12)"),
		  newest:"12.3(12)") ) vuln ++;

# 12.3B
if ( check_release(version:version,
		   patched:make_list("12.3(5a)B3"),
		   newest:"12.3(5a)B3") ) vuln ++;

# 12.3BC
if ( check_release(version:version,
		   patched:make_list("12.3(9a)BC1"),
		   newest:"12.3(9a)BC1") ) vuln ++;
# 12.3T
if ( check_release(version:version,
		   patched:make_list("12.3(4)T11", "12.3(7)T7", "12.3(8)T5", "12.3(11)T"),
		   newest:"12.3(11)T") ) vuln ++;
# 12.3XC
if ( check_release(version:version,
		   patched:make_list("12.3(2)XC3"),
		   newest:"12.3(2)XC3") ) vuln ++;
# 12.3XD
if ( check_release(version:version,
		   patched:make_list("12.3(4)XD4"),
		   newest:"12.3(4)XD4") ) vuln ++;
# 12.3XE
if ( check_release(version:version,
		   patched:make_list("12.3(2)XE1"),
		   newest:"12.3(2)XE1") ) vuln ++;
# 12.3XI
if ( check_release(version:version,
		   patched:make_list("12.3(7)XI3"),
		   newest:"12.3(7)XI3") ) vuln ++;
# 12.3XQ
if ( check_release(version:version,
		   patched:make_list("12.3(4)XQ1"),
		   newest:"12.3(4)XQ1") ) vuln ++;
# 12.3XS
if ( check_release(version:version,
		   patched:make_list("12.3(7)XS2"),
		   newest:"12.3(7)XS2") ) vuln ++;
# 12.3XU
if ( check_release(version:version,
		   patched:make_list("12.3(8)XU4"),
		   newest:"12.3(8)XU4") ) vuln ++;
# 12.3XX
if ( check_release(version:version,
		   patched:make_list("12.3(8)XX1"),
		   newest:"12.3(8)XX1") ) vuln ++;
# 12.3YA
if ( check_release(version:version,
		   patched:make_list("12.3(8)YA1"),
		   newest:"12.3(8)YA1") ) vuln ++;


if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 )  display("Problem in script $Id: CSCee67450.nasl,v 1.2 2006/02/17 16:55:05 renaud Exp $\n");

