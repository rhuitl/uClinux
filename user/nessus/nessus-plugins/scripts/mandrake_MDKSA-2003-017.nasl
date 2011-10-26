#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:017-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14002);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(6753);
 script_cve_id("CVE-2002-1160");
 
 name["english"] = "MDKSA-2003:017-1: pam";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:017-1 (pam).


Andreas Beck discovered that the pam_xauth module would forward authorization
information from the root account to unprivileged users. This can be exploited
by a local attacker to gain access to the root user's X session. In order for it
to be successfully exploited, the attacker would have to somehow get the root
user to su to the account belonging to the attacker.
Update:
The previous fix was incorrect because certain applications, such as userdrake
and net_monitor could not be executed as root, although they could be executed
as users who successfully authenticated as root.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:017-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pam package";
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
if ( rpm_check( reference:"pam-0.75-25.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.75-25.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam-doc-0.75-25.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam-0.75-25.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.75-25.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam-doc-0.75-25.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"pam-", release:"MDK8.2")
 || rpm_exists(rpm:"pam-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1160", value:TRUE);
}
