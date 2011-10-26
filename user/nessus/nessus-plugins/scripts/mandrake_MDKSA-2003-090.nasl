#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:090-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14072);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0020");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0693", "CVE-2003-0695");
 
 name["english"] = "MDKSA-2003:090-1: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:090-1 (openssh).


A buffer management error was discovered in all versions of openssh prior to
version 3.7. According to the OpenSSH team's advisory: 'It is uncertain whether
this error is potentially exploitable, however, we prefer to see bugs fixed
proactively.' There have also been reports of an exploit in the wild.
MandrakeSoft encourages all users to upgrade to these patched openssh packages
immediately and to disable sshd until you are able to upgrade if at all
possible.
Update:
The OpenSSH developers discovered more, similar, problems and revised the patch
to correct these issues. These new packages have the latest patch fix applied.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:090-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssh package";
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
if ( rpm_check( reference:"openssh-3.6.1p2-1.2.82mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.6.1p2-1.2.82mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.6.1p2-1.2.82mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.6.1p2-1.2.82mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.6.1p2-1.2.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.6.1p2-1.2.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.6.1p2-1.2.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.6.1p2-1.2.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.6.1p2-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.6.1p2-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.6.1p2-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.6.1p2-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"openssh-", release:"MDK8.2")
 || rpm_exists(rpm:"openssh-", release:"MDK9.0")
 || rpm_exists(rpm:"openssh-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0693", value:TRUE);
 set_kb_item(name:"CVE-2003-0695", value:TRUE);
}
