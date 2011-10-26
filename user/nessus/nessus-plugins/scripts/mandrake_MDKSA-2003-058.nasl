#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:058-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14042);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0289");
 
 name["english"] = "MDKSA-2003:058-1: cdrecord";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:058-1 (cdrecord).


A vulnerability in cdrecord was discovered that can be used to obtain root
access because Mandrake Linux ships with the cdrecord binary suid root and sgid
cdwriter.
Updated packages are provided that fix this vulnerability. You may also elect to
remove the suid and sgid bits from cdrecord manually, which can be done by
executing, as root:
chmod ug-s /usr/bin/cdrecord
This is not required to protect yourself from this particular vulnerability,
however.
Update:
Two additional format string problems were discovered by Olaf Kirch and an
updated patch has been applied to fix those problems as well.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:058-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cdrecord package";
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
if ( rpm_check( reference:"cdrecord-1.11-0.a31.1.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-cdda2wav-1.11-0.a31.1.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-1.11-0.a31.1.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-dvdhack-1.11-0.a31.1.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkisofs-1.15-0.a31.1.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-1.11-0.a32.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-cdda2wav-1.11-0.a32.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-1.11-0.a32.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-dvdhack-1.11-0.a32.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkisofs-1.15-0.a32.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-2.0-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-cdda2wav-2.0-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-2.0-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-dvdhack-2.0-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkisofs-2.0-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cdrecord-", release:"MDK8.2")
 || rpm_exists(rpm:"cdrecord-", release:"MDK9.0")
 || rpm_exists(rpm:"cdrecord-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0289", value:TRUE);
}
