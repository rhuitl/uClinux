#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:033-2
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14776);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2001:033-2: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:033-2 (openssh).


There are several weaknesses in various implementations of the SSH (Secure
Shell) protocols. When exploited, they let the attacker obtain sensitive
information by passively monitoring encrypted SSH sessions. The information can
later be used to speed up brute-force attacks on passwords, including the
initial login password and other passwords appearing in interactive SSH
sessions, such as those used with su. Versions of OpenSSH 2.5.2 and later have
been fixed to reduce the impact of these traffic analysis problems, and as such
all Linux- Mandrake users are encouraged to upgrade their version of openssh
immediately.
Update:
A problem was introduced with a patch applied to the OpenSSH packages released
in the previous update. This problem was due to the keepalive patch included,
and it broke interoperability with older versions of OpenSSH and SSH. This
update removes the patch, and also provides the latest version of OpenSSH which
provides a number of new features and enhancements.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:033-2
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
if ( rpm_check( reference:"openssh-2.9p1-3.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-2.9p1-3.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-2.9p1-3.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-2.9p1-3.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-2.9p1-3.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-2.9p1-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-2.9p1-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-2.9p1-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-2.9p1-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-2.9p1-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-2.9p1-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-2.9p1-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-2.9p1-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-2.9p1-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-2.9p1-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
