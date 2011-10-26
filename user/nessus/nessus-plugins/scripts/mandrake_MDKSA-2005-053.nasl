#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:053
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17331);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0008");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2005-0699", "CVE-2005-0704", "CVE-2005-0705", "CVE-2005-0739");
 
 name["english"] = "MDKSA-2005:053: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:053 (ethereal).



A number of issues were discovered in Ethereal versions prior to 0.10.10, which
is provided by this update. Matevz Pustisek discovered a buffer overflow in the
Etheric dissector (CVE-2005-0704); the GPRS-LLC dissector could crash if the
'ignore cipher bit' was enabled (CVE-2005-0705); Diego Giago found a buffer
overflow in the 3GPP2 A11 dissector (CVE-2005-0699); Leon Juranic found a
buffer overflow in the IAPP dissector (CVE-2005-0739); and bugs in the JXTA and
sFlow dissectors could make Ethereal crash.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:053
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.10-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.10-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.10-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.10-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.10-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.0")
 || rpm_exists(rpm:"ethereal-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0699", value:TRUE);
 set_kb_item(name:"CVE-2005-0704", value:TRUE);
 set_kb_item(name:"CVE-2005-0705", value:TRUE);
 set_kb_item(name:"CVE-2005-0739", value:TRUE);
}
