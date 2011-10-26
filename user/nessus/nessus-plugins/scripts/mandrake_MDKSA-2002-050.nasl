#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:050
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13953);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0651", "CVE-2002-0684");
 
 name["english"] = "MDKSA-2002:050: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:050 (glibc).


A buffer overflow vulnerability was found in the way that the glibc resolver
handles the resolution of network names and addresses via DNS in glibc versions
2.2.5 and earlier. Only systems using the 'dns' entry in the 'networks' database
in /etc/nsswitch.conf are vulnerable to this issue. By default, Mandrake Linux
has this database set to 'files' and is not vulnerable. Likewise, a similar bug
is in the glibc-compat packages which provide compatability for programs
compiled against 2.0.x versions of glibc.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:050
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the glibc package";
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
if ( rpm_check( reference:"glibc-2.1.3-20.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.1.3-20.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.1.3-20.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.1.3-20.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.1.3-20.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.1.3-20.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.1.3-20.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.1.3-20.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.2-7.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.2-7.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.2-7.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ldconfig-2.2.2-7.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.2-7.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.4-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.4-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.4-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ldconfig-2.2.4-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.4-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.4-25.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.4-25.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.4-25.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ldconfig-2.2.4-25.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.4-25.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"glibc-", release:"MDK7.1")
 || rpm_exists(rpm:"glibc-", release:"MDK7.2")
 || rpm_exists(rpm:"glibc-", release:"MDK8.0")
 || rpm_exists(rpm:"glibc-", release:"MDK8.1")
 || rpm_exists(rpm:"glibc-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0651", value:TRUE);
 set_kb_item(name:"CVE-2002-0684", value:TRUE);
}
