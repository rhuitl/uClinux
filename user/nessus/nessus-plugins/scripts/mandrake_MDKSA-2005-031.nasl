#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:031
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16360);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0452", "CVE-2004-0976", "CVE-2005-0155", "CVE-2005-0156");
 
 name["english"] = "MDKSA-2005:031: perl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:031 (perl).



Jeroen van Wolffelaar discovered that the rmtree() function in the perl
File::Path module would remove directories in an insecure manner which could
lead to the removal of arbitrary files and directories via a symlink attack
(CVE-2004-0452).

Trustix developers discovered several insecure uses of temporary files in many
modules which could allow a local attacker to overwrite files via symlink
attacks (CVE-2004-0976).

'KF' discovered two vulnerabilities involving setuid-enabled perl scripts. By
setting the PERLIO_DEBUG environment variable and calling an arbitrary
setuid-root perl script, an attacker could overwrite arbitrary files with perl
debug messages (CVE-2005-0155). As well, calling a setuid-root perl script with
a very long path would cause a buffer overflow if PERLIO_DEBUG was set, which
could be exploited to execute arbitrary files with root privileges
(CVE-2005-0156).

The provided packages have been patched to resolve these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:031
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl package";
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
if ( rpm_check( reference:"perl-5.8.3-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-base-5.8.3-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-devel-5.8.3-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-doc-5.8.3-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.5-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-base-5.8.5-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-devel-5.8.5-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-doc-5.8.5-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.1-0.RC4.3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-base-5.8.1-0.RC4.3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-devel-5.8.1-0.RC4.3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-doc-5.8.1-0.RC4.3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"perl-", release:"MDK10.0")
 || rpm_exists(rpm:"perl-", release:"MDK10.1")
 || rpm_exists(rpm:"perl-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0452", value:TRUE);
 set_kb_item(name:"CVE-2004-0976", value:TRUE);
 set_kb_item(name:"CVE-2005-0155", value:TRUE);
 set_kb_item(name:"CVE-2005-0156", value:TRUE);
}
