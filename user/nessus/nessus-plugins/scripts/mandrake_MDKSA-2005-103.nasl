#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:103
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18550);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1993");
 
 name["english"] = "MDKSA-2005:103: sudo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:103 (sudo).



A race condition was discovered in sudo by Charles Morris. This could lead to
the escalation of privileges if /etc/sudoers allowed a user to execute selected
programs that were then followed by another line containing the pseudo-command
'ALL'. By creating symbolic links at a certain time, that user could execute
arbitrary commands.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:103
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sudo package";
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
if ( rpm_check( reference:"sudo-1.6.7-0.p5.2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p1-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p1-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sudo-", release:"MDK10.0")
 || rpm_exists(rpm:"sudo-", release:"MDK10.1")
 || rpm_exists(rpm:"sudo-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1993", value:TRUE);
}
