#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:138-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19895);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2097");
 
 name["english"] = "MDKSA-2005:138-1: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:138-1 (cups).



A vulnerability was discovered in the CUPS printing package where when
processing a PDF file, bounds checking was not correctly performed on some
fields. As a result, this could cause the pdtops filter to crash.

Update:

The patch to correct this problem was not properly applied to the Mandriva 10.1
packages. This update properly patches the packages.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:138-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups package";
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
if ( rpm_check( reference:"cups-1.1.21-0.rc1.7.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.21-0.rc1.7.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.21-0.rc1.7.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.1.21-0.rc1.7.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.1.21-0.rc1.7.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-2097", value:TRUE);
}
