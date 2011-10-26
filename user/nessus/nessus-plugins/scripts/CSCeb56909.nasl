#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17630);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0002");
 script_bugtraq_id(12369);
 script_version("$Revision: 1.2 $");

 name["english"] = "Cisco IOS MPLS Remote Denial of Service";

 script_name(english:name["english"]);

 desc["english"] = "
The remote version of IOS is vulnerable to a denial of service vulnerability when
processing malformed MPLS packets.

If IPv6 is enabled, an attacket may exploit this flaw to prevent the router from
working properly.

Solution : http://www.cisco.com/warp/public/707/cisco-sa-20050126-les.shtml
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

if ( ereg(pattern:"cisco[^0-9]*(26.0|28.0|3[678].0|4[57].0|5[34][.]0)$", string:hardware) )
	exit(0);


# 12.1 Deprecated
if ( deprecated_version(version, "12.1DB", "12.1DC", "12.1T", "12.1XG", "12.1XI", "12.1XJ", "12.1XL", "12.1XM", "12.1XP", "12.1XQ", "12.1XR", "12.1XT", "12.1XU", "12.1XV", "12.1YA", "12.1YB", "12.1YC", "12.1YD", "12.1YE", "12.1YF", "12.1YH", "12.1YI")) vuln ++;

# 12.2 Deprecated
if ( deprecated_version(version, "12.2B", "12.2BW", "12.2BX", "12.2BY", "12.2BZ", "12.2CX", "12.2CY", "12.2DD", "12.2DX", "12.2MB", "12.2MC", "12.2MX", "12.2SY", "12.2SZ", "12.2XA", "12.2XC", "12.2XD", "12.2XE", "12.2XF", "12.2XG", "12.2XH", "12.2XI", "12.2XJ", "12.2XK", "12.2XL", "12.2XM", "12.2XN", "12.2XQ", "12.2XS", "12.2XT", "12.2XU", "12.2XV", "12.2XW", "12.2XZ", "12.2YB", "12.2YC", "12.2YD", "12.2YE", "12.2YF", "12.2YG", "12.2YH", "12.2YI", "12.2YJ", "12.2YL", "12.2YM", "12.2YN", "12.2YO", "12.2YQ", "12.2YQ", "12.2YR", "12.2YS", "12.2YU", "12.2YV", "12.2YW", "12.2YX", "12.2YZ", "12.2ZB", "12.2ZC", "12.2ZD", "12.2ZE", "12.2ZF", "12.2ZG", "12.2ZH", "12.2ZI", "12.2ZJ", "12.2ZL", "12.2ZN", "12.2ZO", "12.2ZP") ) vuln ++;

# 12.3 Deprecated
if ( deprecated_version(version, "12.3BW", "12.3XA", "12.3XB") ) vuln ++;



# 12.2
if ( check_release(version:version,
		   patched:make_list("12.2(10g)", "12.2(13e)", "12.2(16f)", "12.2(17d)", "12.2(19b)", "12.2(21a)", "12.2(23)"),
		   newest:"12.2(23)") ) vuln ++;


# 12.2BC
if ( check_release(version:version,
		   patched:make_list("12.2(15)BC2"),
		   newest:"12.2(15)BC2") ) vuln ++;
# 12.2CZ
if ( check_release(version:version,
		   patched:make_list("12.2(15)CZ"),
		   newest:"12.2(15)CZ") ) vuln ++;
# 12.2DA
if ( check_release(version:version,
		   patched:make_list("12.2(12)DA6"),
		   newest:"12.2(12)DA6") ) vuln ++;
# 12.2EW
if ( check_release(version:version,
		   patched:make_list("12.2(18)EW"),
		   newest:"12.2(18)EW") ) vuln ++;
# 12.2EWA
if ( check_release(version:version,
		   patched:make_list("12.2(20)EWA"),
		   newest:"12.2(20)EWA") ) vuln ++;
# 12.2JA
if ( check_release(version:version,
		   patched:make_list("12.2(15)JA"),
		   newest:"12.2(15)JA") ) vuln ++;

# 12.2JK
if ( check_release(version:version,
		   patched:make_list("12.2(15)JK"),
		   newest:"12.2(15)JK") ) vuln ++;
# 12.2SU
if ( check_release(version:version,
		   patched:make_list("12.2(14)SU"),
		   newest:"12.2(14)SU") ) vuln ++;
# 12.2SW
if ( check_release(version:version,
		   patched:make_list("12.2(19)SW"),
		   newest:"12.2(19)SW") ) vuln ++;

# 12.2T
if ( check_release(version:version,
		   patched:make_list("12.2(13)T14", "12.2(15)T7"),
		   newest:"12.2(15)T7") ) vuln ++;
# 12.2XR
if ( check_release(version:version,
		   patched:make_list("12.2(15)XR"),
		   newest:"12.2(15)XR") ) vuln ++;
# 12.2YA
if ( check_release(version:version,
		   patched:make_list("12.2(4)YA8"),
		   newest:"12.2(4)YA8") ) vuln ++;

# 12.2YA
if ( check_release(version:version,
		   patched:make_list("12.2(4)YA8"),
		   newest:"12.2(4)YA8") ) vuln ++;


# 12.3
if ( check_release(version:version,
		   patched:make_list("12.3(3f)", "12.3(5)"),
		   newest:"12.3(5)") ) vuln ++;


# 12.3B
if ( check_release(version:version,
		   patched:make_list("12.3(5a)B4"),
		   newest:"12.3(5a)B4") ) vuln ++;
# 12.3BC
if ( check_release(version:version,
		   patched:make_list("12.3(9a)BC"),
		   newest:"12.3(9a)BC") ) vuln ++;

# 12.3T
if ( check_release(version:version,
		   patched:make_list("12.3(2)T5", "12.3(4)T7", "12.3(7)T"),
		   newest:"12.3(7)T") ) vuln ++;
# 12.3XC
if ( check_release(version:version,
		   patched:make_list("12.3(2)XC3"),
		   newest:"12.3(2)XC3") ) vuln ++;

# 12.3XD
if ( check_release(version:version,
		   patched:make_list("12.3(4)XD"),
		   newest:"12.3(4)XD") ) vuln ++;
# 12.3XE
if ( check_release(version:version,
		   patched:make_list("12.3(2)XE1"),
		   newest:"12.3(2)XE1") ) vuln ++;
# 12.3XF
if ( check_release(version:version,
		   patched:make_list("12.3(2)XF"),
		   newest:"12.3(2)XF") ) vuln ++;
# 12.3XG
if ( check_release(version:version,
		   patched:make_list("12.3(4)XG1"),
		   newest:"12.3(4)XG1") ) vuln ++;
# 12.3XH
if ( check_release(version:version,
		   patched:make_list("12.3(4)XH"),
		   newest:"12.3(4)XH") ) vuln ++;
# 12.3XI
if ( check_release(version:version,
		   patched:make_list("12.3(7)XI"),
		   newest:"12.3(7)XI") ) vuln ++;
# 12.3XJ
if ( check_release(version:version,
		   patched:make_list("12.3(7)XJ"),
		   newest:"12.3(7)XJ") ) vuln ++;
# 12.3XK
if ( check_release(version:version,
		   patched:make_list("12.3(4)XK1"),
		   newest:"12.3(4)XK1") ) vuln ++;
# 12.3XL
if ( check_release(version:version,
		   patched:make_list("12.3(7)XL"),
		   newest:"12.3(7)XL") ) vuln ++;
# 12.3XM
if ( check_release(version:version,
		   patched:make_list("12.3(7)XM"),
		   newest:"12.3(7)XM") ) vuln ++;

# 12.3XN
if ( check_release(version:version,
		   patched:make_list("12.3(4)XN"),
		   newest:"12.3(4)XN") ) vuln ++;
# 12.3XQ
if ( check_release(version:version,
		   patched:make_list("12.3(4)XQ"),
		   newest:"12.3(4)XQ") ) vuln ++;
# 12.3XR
if ( check_release(version:version,
		   patched:make_list("12.3(7)XR"),
		   newest:"12.3(7)XR") ) vuln ++;
# 12.3XS
if ( check_release(version:version,
		   patched:make_list("12.3(7)XS"),
		   newest:"12.3(7)XS") ) vuln ++;
# 12.3XT
if ( check_release(version:version,
		   patched:make_list("12.3(2)XT"),
		   newest:"12.3(2)XT") ) vuln ++;
# 12.3XU
if ( check_release(version:version,
		   patched:make_list("12.3(8)XU"),
		   newest:"12.3(8)XU") ) vuln ++;
# 12.3XW
if ( check_release(version:version,
		   patched:make_list("12.3(8)XW"),
		   newest:"12.3(8)XW") ) vuln ++;
# 12.3XX
if ( check_release(version:version,
		   patched:make_list("12.3(8)XX"),
		   newest:"12.3(8)XX") ) vuln ++;
# 12.3XY
if ( check_release(version:version,
		   patched:make_list("12.3(8)XY"),
		   newest:"12.3(8)XY") ) vuln ++;
# 12.3XA
if ( check_release(version:version,
		   patched:make_list("12.3(8)XA"),
		   newest:"12.3(8)XA") ) vuln ++;
# 12.3XD
if ( check_release(version:version,
		   patched:make_list("12.3(8)XD"),
		   newest:"12.3(8)XD") ) vuln ++;

# 12.3XE
if ( check_release(version:version,
		   patched:make_list("12.3(4)XE"),
		   newest:"12.3(4)XE") ) vuln ++;
# 12.3XF
if ( check_release(version:version,
		   patched:make_list("12.3(11)XF"),
		   newest:"12.3(11)XF") ) vuln ++;
# 12.3XG
if ( check_release(version:version,
		   patched:make_list("12.3(8)XG"),
		   newest:"12.3(8)XG") ) vuln ++;
# 12.3XH
if ( check_release(version:version,
		   patched:make_list("12.3(8)XH"),
		   newest:"12.3(8)XH") ) vuln ++;


if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 ) display("Problem in script $Id: CSCeb56909.nasl,v 1.2 2006/03/13 20:03:12 jwlampe Exp $\n");
