#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:033
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14017);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0107");
 
 name["english"] = "MDKSA-2003:033: zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:033 (zlib).


Richard Kettlewell discovered a buffer overflow vulnerability in the zlib
library's gzprintf() function. This can be used by attackers to cause a denial
of service or possibly even the execution of arbitrary code. Our thanks to the
OpenPKG team for providing a patch which adds the necessary configure script
checks to always use the secure vsnprintf(3) and snprintf(3) functions, and
which additionally adjusts the code to correctly take into account the return
value of vsnprintf(3) and snprintf(3).


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:033
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zlib package";
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
if ( rpm_check( reference:"zlib-1.1.3-11.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.1.3-11.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.3-16.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.3-16.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.3-16.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.3-16.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.3-19.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.3-19.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.4-5.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.4-5.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"zlib-", release:"MDK7.2")
 || rpm_exists(rpm:"zlib-", release:"MDK8.0")
 || rpm_exists(rpm:"zlib-", release:"MDK8.1")
 || rpm_exists(rpm:"zlib-", release:"MDK8.2")
 || rpm_exists(rpm:"zlib-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0107", value:TRUE);
}
