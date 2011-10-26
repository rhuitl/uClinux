#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:085
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14334);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");
 
 name["english"] = "MDKSA-2004:085: qt3";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:085 (qt3).


Chris Evans discovered a heap-based overflow in the QT library when handling
8-bit RLE encoded BMP files. This vulnerability could allow for the compromise
of the account used to view or browse malicious BMP files. On subsequent
investigation, it was also found that the handlers for XPM, GIF, and JPEG image
types were also faulty.
These problems affect all applications that use QT to handle image files, such
as QT-based image viewers, the Konqueror web browser, and others.
The updated packages have been patched to correct these problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:085
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the qt3 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libqt3-3.2.3-19.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libqt3-devel-3.2.3-19.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libqt3-mysql-3.2.3-19.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libqt3-odbc-3.2.3-19.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libqt3-psql-3.2.3-19.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-common-3.2.3-19.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-example-3.2.3-19.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libqt3-3.1.2-15.4.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libqt3-devel-3.1.2-15.4.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libqt3-mysql-3.1.2-15.4.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libqt3-odbc-3.1.2-15.4.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libqt3-psql-3.1.2-15.4.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-common-3.1.2-15.4.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-example-3.1.2-15.4.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"qt3-", release:"MDK10.0")
 || rpm_exists(rpm:"qt3-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0691", value:TRUE);
 set_kb_item(name:"CVE-2004-0692", value:TRUE);
 set_kb_item(name:"CVE-2004-0693", value:TRUE);
}
