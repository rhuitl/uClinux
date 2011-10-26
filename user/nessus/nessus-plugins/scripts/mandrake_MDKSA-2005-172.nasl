#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:172
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20426);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2798");
 
 name["english"] = "MDKSA-2005:172: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:172 (openssh).



Sshd in OpenSSH before 4.2, when GSSAPIDelegateCredentials is enabled, allows
GSSAPI credentials to be delegated to clients who log in using non-GSSAPI
methods, which could cause those credentials to be exposed to untrusted users
or hosts.

GSSAPI is only enabled in versions of openssh shipped in LE2005 and greater.

The updated packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:172
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssh package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssh-3.9p1-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.9p1-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.9p1-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.9p1-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"openssh-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2798", value:TRUE);
}
