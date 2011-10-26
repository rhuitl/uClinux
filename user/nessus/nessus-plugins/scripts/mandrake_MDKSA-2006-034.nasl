#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:034
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20875);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0225");
 
 name["english"] = "MDKSA-2006:034: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:034 (openssh).



A flaw was discovered in the scp local-to-local copy implementation where
filenames that contain shell metacharacters or spaces are expanded twice, which
could lead to the execution of arbitrary commands if a local user could be
tricked into a scp'ing a specially crafted filename. The provided updates bump
the OpenSSH version to the latest release version of 4.3p1. A number of
differences exist, primarily dealing with PAM authentication over the version
included in Corporate 3.0 and MNF2. In particular, the default sshd_config now
only accepts protocol 2 connections and UsePAM is now disabled by default. On
systems using alternate authentication methods (ie. LDAP) that use the PAM
stack for authentication, you will need to enable UsePAM. Note that the default
/etc/pam.d/sshd file has also been modified to use the pam_listfile.so module
which will deny access to any users listed in /etc/ssh/denyusers (by default,
this is only the root user). This is required to preserve the expected
behaviour when using 'PermitRootLogin without-password'; otherwise it would
still be possible to obtain a login prompt and login without using keys.
Mandriva Linux 10.1 and newer already have these changes in their shipped
versions. There are new features in OpenSSH and users are encouraged to review
the new sshd_config and ssh_config files when upgrading.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:034
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
if ( rpm_check( reference:"openssh-4.3p1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.3p1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-4.3p1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-4.3p1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-4.3p1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-4.3p1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.3p1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-4.3p1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-4.3p1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-4.3p1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-4.3p1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.3p1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-4.3p1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-4.3p1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-4.3p1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"openssh-", release:"MDK10.1")
 || rpm_exists(rpm:"openssh-", release:"MDK10.2")
 || rpm_exists(rpm:"openssh-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0225", value:TRUE);
}
