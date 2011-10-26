#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:008
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13993);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1363");
 
 name["english"] = "MDKSA-2003:008: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:008 (libpng).


A buffer overflow vulnerability was discovered in libpng due to a wrong
calculation of some loop offset values. This buffer overflow can lead to Denial
of Service or even remote compromise.
After the upgrade, all applications that use libpng should be restarted. Many
applications are linked to libpng, so if you are unsure of what applications to
restart, you may wish to reboot the system. MandrakeSoft encourages all users to
upgrade immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:008
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng package";
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
if ( rpm_check( reference:"libpng-1.0.8-2.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.0.8-2.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng2-1.0.9-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng2-devel-1.0.9-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng2-1.0.12-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng2-devel-1.0.12-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.4-3.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.4-3.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.4-3.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.4-3.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.4-3.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.4-3.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libpng-", release:"MDK7.2")
 || rpm_exists(rpm:"libpng-", release:"MDK8.0")
 || rpm_exists(rpm:"libpng-", release:"MDK8.1")
 || rpm_exists(rpm:"libpng-", release:"MDK8.2")
 || rpm_exists(rpm:"libpng-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1363", value:TRUE);
}
