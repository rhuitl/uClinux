#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:127
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15638);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0989");
 
 name["english"] = "MDKSA-2004:127: libxml/libxml2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:127 (libxml/libxml2).



Multiple buffer overflows were reported in the libxml XML parsing library.
These vulnerabilities may allow remote attackers to execute arbitray code via a
long FTP URL that is not properly handled by the xmlNanoFTPScanURL() function,
a long proxy URL containing FTP data that is not properly handled by the
xmlNanoFTPScanProxy() function, and other overflows in the code that resolves
names via DNS.

The updated packages have been patched to prevent these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:127
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libxml/libxml2 package";
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
if ( rpm_check( reference:"libxml1-1.8.17-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml1-devel-1.8.17-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-2.6.6-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.6.6-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.6.6-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-utils-2.6.6-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml1-1.8.17-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml1-devel-1.8.17-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-2.6.13-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.6.13-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.6.13-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-utils-2.6.13-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml1-1.8.17-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml1-devel-1.8.17-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-2.5.11-1.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.5.11-1.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.5.11-1.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-utils-2.5.11-1.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libxml-", release:"MDK10.0")
 || rpm_exists(rpm:"libxml-", release:"MDK10.1")
 || rpm_exists(rpm:"libxml-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0989", value:TRUE);
}
