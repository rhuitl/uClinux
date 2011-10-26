#
# (C) Tenable Network Security
#


if(description)
{
 script_id(20134);
 script_bugtraq_id(15275);
 script_version("$Revision: 1.2 $");

 name["english"] = "CISCO IOS Timers Heap Buffer Overflow Vulnerability";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote router can be compromised remotely.

Description :

The remote host is a CISCO router containing a version of IOS which is
vulnerable to a heap overflow vulnerability.

An attacker may exploit this flaw to crash the remote device or to execute
arbitrary code remotely.

Solution :

http://www.cisco.com/warp/public/707/cisco-sa-20051102-timers.shtml

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:I)";


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
if ( deprecated_version(version, "12.0DA", "12.0DB", "12.0DC", "12.0SC", 
				 "12.0SL", "12.0SP", "12.0ST", "12.0SX", 
				 "12.0SZ", "12.0T",  "12.0XA", "12.0XB", 
				 "12.0XC", "12.0XD", "12.0XE", "12.0XF", 
				 "12.0XG", "12.0XH", "12.0XH", "12.0XI", 
				 "12.0XJ", "12.0XK", "12.0XL", "12.0XM",
				 "12.0XN", "12.0XQ", "12.0XR", "12.0XS", 
				 "12.0XV") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.0(28d)"),
		   newest:"12.0(28d)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.0(28)S5", "12.0(30)S4", "12.0(31)S1"),
		   newest:"12.0(31)S1") ) vuln ++;


# 12.1

if ( deprecated_version(version, "12.1AA", "12.1AX", "12.1AY", "12.1AZ", 
				 "12.1CX", "12.1DA", "12.1DB", "12.1DC",
				 "12.1EB", "12.1EU", "12.1EV", "12.1EX",
				 "12.1EY", "12.1EZ", "12.1T",  "12.1XA",
				 "12.1XB", "12.1XC", "12.1XD", "12.1XE",
				 "12.1XF", "12.1XG", "12.1XH", "12.1XI",
				 "12.1XJ", "12.1XL", "12.1XM", "12.1XP",
				 "12.1XQ", "12.1XR", "12.1XS", "12.1XT",
				 "12.1XU", "12.1XV", "12.1XW", "12.1XX",
				 "12.1XY", "12.1YA", "12.1YB", "12.1YC",
				 "12.1YD", "12.1YE", "12.1YF", "12.1YH",
				 "12.1YI", "12.1YJ") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(27b)"),
		   newest:"12.1(27b)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(8b)E20", "12.1(13)E17", "12.1(23)E4", "12.1(26)E3"),
		   newest:"12.1(26)E3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(26)EB1"),
		   newest:"12.1(26)EB1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(20)EO3"),
		   newest:"12.1(20)EO3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(12c)EW4", "12.1(13)EW4", "12.1(19)EW3", "12.1(20)EW4" ),
		   newest:"12.1(20)EW4") ) vuln ++;


# 12.2
if ( deprecated_version(version, "12.2B", "12.2BX", "12.2BY", "12.2BZ", "12.2CX", "12.2CY", "12.2DD", "12.2DX", "12.2EZ", "12.2JA", "12.2SU", "12.2SX", "12.2SXA", "12.2SY", "12.2SZ", "12.2XA", "12.2XB", "12.2XC", "12.2XD", "12.2XE", "12.2XF", "12.2XG", "12.2XH", "12.2XI", "12.2XJ", "12.2XK", "12.2XL", "12.2XM", "12.2XN", "12.2XQ", "12.2XS", "12.2XT", "12.2XU", "12.2XV", "12.2XW", "12.2YB", "12.2YC", "12.2YD", "12.2YE", "12.2YF", "12.2YG", "12.2YH", "12.2YJ", "12.2YJ", "12.2YK", "12.2YL", "12.2YM", "12.2YN", "12.2YO", "12.2YP", "12.2YQ", "12.2YR", "12.2YT", "12.2YU", "12.2YV", "12.2YW", "12.2YX", "12.2YY", "12.2YZ", "12.2ZA", "12.2ZB", "12.2ZC", "12.2ZE", "12.2ZF", "12.2ZG", "12.2ZJ", "12.2ZL", "12.2ZN", "12.2ZP" ) ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.2(12m)", "12.2(17f)", "12.2(23f)", "12.2(26b)", "12.2(27b)", "12.2(28c)", "12.2(29a)", "12.2(31)"),
		   newest:"12.2(31)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(15)BC2i" ),
		   newest:"12.2(15)BC2i") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(15)CZ3" ),
		   newest:"12.2(15)CZ3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(10)DA4", "12.2(12)DA9"),
		   newest:"12.2(12)DA9") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(20)EU2"),
		   newest:"12.2(20)EU2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)EW5", "12.2(20)EW3"),
		   newest:"12.2(20)EW3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(20)EWA3", "12.2(25)EWA3", "12.2(25)EWA4"),
		   newest:"12.2(25)EW4") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)EX"),
		   newest:"12.2(25)EX") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)EY3"),
		   newest:"12.2(25)EY3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)FX"),
		   newest:"12.2(25)FX") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)FY"),
		   newest:"12.2(25)FY") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(14)S15", "12.2(18)S10", "12.2(20)S9", "12.2(25)S6", "12.2(30)S1"),
		   newest:"12.2(30)S1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(27)SBC"),
		   newest:"12.2(27)SBC") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)SEB4", "12.2(25)SEC2", "12.2(25)SED"),
		   newest:"12.2(25)SED") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)SG"),
		   newest:"12.2(25)SG") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)SO4"),
		   newest:"12.2(18)SO4") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(26)SV1", "12.2(27)SV1"),
		   newest:"12.2(27)SV1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)SW4", "12.2(25)SW4a"),
		   newest:"12.2(25)SW4a") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(17d)SXB10"),
		   newest:"12.2(17d)SXB10") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.2(18)SXD6"),
		   newest:"12.2(18)SXD6") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)SXE3"),
		   newest:"12.2(18)SXE3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)SXF"),
		   newest:"12.2(18)SXF") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(15)T17"),
		   newest:"12.2(15)T17") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(8)TPC10a"),
		   newest:"12.2(8)TPC10a") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(4)YA11"),
		   newest:"12.2(4)YA11") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(15)YS"),
		   newest:"12.2(15)YS") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(13)ZH8"),
		   newest:"12.2(13)ZH8") ) vuln ++;



#
# 12.3
#

if ( deprecated_version(version, "12.3B", "12.3BW", "12.3XB", "12.3XD", "12.3XF", "12.3XH", "12.3XJ", "12.3XM", "12.3XQ", "12.3XS", "12.3XU", "12.3XW", "12.3XX", "12.3XY", "12.3YA", "12.3YD", "12.3YH") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.3(3i)", "12.3(5f)", "12.3(6f)", "12.3(9e)", "12.3(10e)", "12.3(12e)", "12.3(13b)", "12.3(15b)", "12.3(16)"),
		   newest:"12.3(16)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(9a)BC7", "12.3(13a)BC1"),
		   newest:"12.3(13a)BC1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)JA5", "12.3(4)JA1", "12.3(7)JA1"),
		   newest:"12.3(7)JA1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)JK1"),
		   newest:"12.3(2)JK1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)JX"),
		   newest:"12.3(7)JX") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)T12", "12.3(8)T11", "12.3(11)T8", "12.3(14)T4"),
		   newest:"12.3(14)T4") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(4)TPC11a"),
		   newest:"12.3(14)TPC11a") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)XA5"),
		   newest:"12.3(2)XA5") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)XC4"),
		   newest:"12.3(2)XC4") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(4)XE4"),
		   newest:"12.3(4)XE4") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(4)XG5"),
		   newest:"12.3(4)XG5") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)XI7"),
		   newest:"12.3(7)XI7") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)XR6"),
		   newest:"12.3(7)XR6") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YF4"),
		   newest:"12.3(11)YF4") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YG3"),
		   newest:"12.3(8)YG3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YI3"),
		   newest:"12.3(8)YI3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YQ3"),
		   newest:"12.3(14)YQ3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YK2"),
		   newest:"12.3(11)YK2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YQ3"),
		   newest:"12.3(14)YQ3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YS1"),
		   newest:"12.3(11)YS1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YT1"),
		   newest:"12.3(14)YT1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YU1"),
		   newest:"12.3(14)YU1") ) vuln ++;

# 12.4

if ( check_release(version:version, 
		   patched:make_list("12.4(1b)", "12.4(3a)"),
		   newest:"12.4(3a)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)MR1"),
		   newest:"12.4(2)MR1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)T1"),
		   newest:"12.4(2)T1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)XA"),
		   newest:"12.4(2)XA") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)XB"),
		   newest:"12.4(2)XB") ) vuln ++;

if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 )  display("Problem in script $Id: CSCei61732.nasl,v 1.2 2005/11/03 15:14:27 renaud Exp $\n");


