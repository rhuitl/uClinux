#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:227
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20458);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3651");
 
 name["english"] = "MDKSA-2005:227: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:227 (ethereal).



A stack-based buffer overflow was discovered in the OSPF dissector in Ethereal.
This could potentially be abused to allow remote attackers to execute arbitrary
code via crafted packets. The updated packages have been patched to prevent
this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:227
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.13-0.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.13-0.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.13-0.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.13-0.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3651", value:TRUE);
}
