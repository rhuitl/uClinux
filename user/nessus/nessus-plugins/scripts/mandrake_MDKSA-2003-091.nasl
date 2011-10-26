#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:091
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14073);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0690", "CVE-2003-0692");
 
 name["english"] = "MDKSA-2003:091: kdebase";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:091 (kdebase).


A vulnerability was discovered in all versions of KDE 2.2.0 up to and including
3.1.3. KDM does not check for successful completion of the pam_setcred() call
and in the case of error conditions in the installed PAM modules, KDM may grant
local root access to any user with valid login credentials. It has been reported
to the KDE team that a certain configuration of the MIT pam_krb5 module can
result in a failing pam_setcred() call which leaves the session alive and would
provide root access to any regular user. It is also possible that this
vulnerability can likewise be exploited with other PAM modules in a similar
manner.
Another vulnerability was discovered in kdm where the cookie session generating
algorithm was considered too weak to supply a full 128 bits of entropy. This
allowed unauthorized users to brute-force the session cookie.
mdkkdm, a specialized version of kdm, is likewise vulnerable to these problems
and has been patched as well.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:091
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdebase package";
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
if ( rpm_check( reference:"kdebase-3.0.5a-1.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.0.5a-1.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-nsplugins-3.0.5a-1.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-3.1-83.5mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.1-83.5mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kdm-3.1-83.5mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-nsplugins-3.1-83.5mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mdkkdm-9.1-24.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdebase-", release:"MDK9.0")
 || rpm_exists(rpm:"kdebase-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0690", value:TRUE);
 set_kb_item(name:"CVE-2003-0692", value:TRUE);
}
