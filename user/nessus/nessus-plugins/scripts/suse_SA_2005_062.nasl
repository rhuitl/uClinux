#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:062
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20083);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:062: permissions";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:062 (permissions).


SUSE LINUX ships with three pre defined sets of permissions, 'easy',
'secure' and 'paranoid'. The chkstat program contained in the
permissions package is used to set those permissions to the chosen
level. Level 'easy' which is the default allows some world writeable
directories. /usr/src/packages/RPMS and subdirectories is among
them. To prevent users from playing tricks in there e.g. linking to
/etc/shadow chkstat doesn't touch symlinks or files with an hardlink
count != 1.

Stefan Nordhausen discovered a way to trick this check. To gain
access to e.g. /etc/shadow a malicious user has to place a hardlink
to that file at a place that is modified by chkstat. chkstat will
not touch the file because it has a hardlink count of two. However,
if the administrator modifies the user database the original
/etc/shadow gets deleted and replaced by a new one. That means the
hardlink count of the file created by the malicious user drops to
one. At this point chkstat will modify the file's permissions so
anyone can read it. So it's technically impossible for chkstat to
modify permissions of files in world writeable directories in a
secure way.

One such world writeable directoy in level 'easy' is
/usr/src/packages/RPMS. Only subdirectories need to be adjusted in
this case. Since normal users cannot create hard links to
directories the problem can be solved by telling chkstat to not
accept regular files. Another problematic directory is /var/games.
Only members of group 'games' may write to it but it's likely that
games with setgid 'games' are exploitable to allow user to gain
group 'games' membership.

The updated permissions package now tells chkstat when to only
accept directories and no longer touches anything below /var/games
to solve the described problems. On SUSE Linux 9.0 xmcd contained
world writeable directories that suffered from the same problems.
Updated xmcd packages for SUSE Linux 9.0 are therefore provided as
well.

We like to thank Stefan Nordhausen for pointing out the problems.


Solution : http://www.suse.de/security/advisories/2005_62_permissions.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the permissions package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"filesystem-10.0-4.2", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"permissions-2005.10.20-0.1", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"permissions-2005.10.20-3", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"xmcd-3.0.2-552", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"permissions-2005.10.20-0.2", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"permissions-2005.10.20-0.1", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"permissions-2005.10.20-0.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
