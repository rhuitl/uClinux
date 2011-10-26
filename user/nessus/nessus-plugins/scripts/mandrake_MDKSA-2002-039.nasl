#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:039-2
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14778);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-0392");
 
 name["english"] = "MDKSA-2002:039-2: apache";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:039-2 (apache).


[ Please note that this advisory supersedes the previous MDKSA-2002:039 and
MDKSA-2002:039-1 advisories. ]
MandrakeSoft is urging all users of Mandrake Linux to update their Apache
installations immediately. What was previously thought to have been a DoS-only
condition has now been proven to be more than that; exploitable conditions have
been discovered on both 32bit and 64bit platforms. Successful exploitation of
this vulnerability may lead to the execution of arbitary code on the server
running a vulnerable Apache with the permissions of the web server child process
(on Mandrake Linux this is the user 'apache'). This can be used to exploit other
vulnerabilities that are unrelated to Apache on the local system, and
potentially allow the intruder root access.
Thanks to Gobbles for proving that this exploitable condition exists. Because
there are known exploits in the wild for some platforms, this update should be
considered essential and should be performed immediately.
All versions of Apache prior to 1.3.26 and 2.0.37 are vulnerable to this
problem. MandrakeSoft has provided patched versions of Apache to correct this
vulnerability.
Also please note that these packages are no different than those provided in
MDKSA-2002:039-1 so if you have already updated, there are no new packages to
upgrade.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:039-2
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache package";
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
if ( rpm_check( reference:"apache-1.3.22-10.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-common-1.3.22-10.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.22-10.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.22-10.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-mod_perl-1.3.22_1.26-2.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-modules-1.3.22-10.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-source-1.3.22-10.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-common-1.3.22_1.26-2.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-devel-1.3.22_1.26-2.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"HTML-Embperl-1.3.22_1.3.4-2.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-1.3.22-10.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-common-1.3.22-10.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.22-10.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.22-10.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-mod_perl-1.3.22_1.26-2.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-modules-1.3.22-10.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-source-1.3.22-10.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-common-1.3.22_1.26-2.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-devel-1.3.22_1.26-2.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"HTML-Embperl-1.3.22_1.3.4-2.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-1.3.22-10.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-common-1.3.22-10.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.22-10.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.22-10.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-mod_perl-1.3.22_1.26-2.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-modules-1.3.22-10.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-source-1.3.22-10.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-common-1.3.22_1.26-2.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-devel-1.3.22_1.26-2.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"HTML-Embperl-1.3.22_1.3.4-2.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-1.3.22-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-common-1.3.22-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.22-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.22-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-mod_perl-1.3.22_1.26-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-modules-1.3.22-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-source-1.3.22-10.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-common-1.3.22_1.26-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-devel-1.3.22_1.26-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"HTML-Embperl-1.3.22_1.3.4-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-1.3.23-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-common-1.3.23-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.23-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.23-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-mod_perl-1.3.23_1.26-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-modules-1.3.23-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-source-1.3.23-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-common-1.3.23_1.26-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_perl-devel-1.3.23_1.26-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"HTML-Embperl-1.3.23_1.3.4-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"apache-", release:"MDK7.1")
 || rpm_exists(rpm:"apache-", release:"MDK7.2")
 || rpm_exists(rpm:"apache-", release:"MDK8.0")
 || rpm_exists(rpm:"apache-", release:"MDK8.1")
 || rpm_exists(rpm:"apache-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0392", value:TRUE);
}
