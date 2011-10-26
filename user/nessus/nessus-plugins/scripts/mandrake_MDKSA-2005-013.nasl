#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:013
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16241);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0006", "CVE-2005-0007", "CVE-2005-0008", "CVE-2005-0009", "CVE-2005-0010", "CVE-2005-0084");
 
 name["english"] = "MDKSA-2005:013: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:013 (ethereal).



A number of vulnerabilities were found in Ethereal, all of which are fixed in
version 0.10.9: The COPS dissector could go into an infinite loop
(CVE-2005-0006); the DLSw dissector could cause an assertion, making Ethereal
exit prematurely (CVE-2005-0007); the DNP dissector could cause memory
corruption (CVE-2005-0008); the Gnutella dissector could cause an assertion,
making Ethereal exit prematurely (CVE-2005-0009); the MMSE dissector could free
static memory (CVE-2005-0010); and the X11 protocol dissector is vulnerable to
a string buffer overflow (CVE-2005-0084).



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:013
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
if ( rpm_check( reference:"ethereal-0.10.9-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.9-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.9-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.9-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.9-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.0")
 || rpm_exists(rpm:"ethereal-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0006", value:TRUE);
 set_kb_item(name:"CVE-2005-0007", value:TRUE);
 set_kb_item(name:"CVE-2005-0008", value:TRUE);
 set_kb_item(name:"CVE-2005-0009", value:TRUE);
 set_kb_item(name:"CVE-2005-0010", value:TRUE);
 set_kb_item(name:"CVE-2005-0084", value:TRUE);
}
