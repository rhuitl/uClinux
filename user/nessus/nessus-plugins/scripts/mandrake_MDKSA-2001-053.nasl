#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:053-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13870);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MDKSA-2001:053-1: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:053-1 (gnupg).


A format string vulnerability exists in gnupg 1.0.5 and previous versions which
is fixed in 1.0.6. This vulnerability can be used to invoke shell commands with
privileges of the currently logged-in user.
Update:
The /usr/bin/gpg executable was installed setuid root and setgid root. While
being setuid root offers locking pages in physical memory to avoid writing
sensitive material to swap and is of benefit, being setgid root provides no
benefits and allows users to write to files that have group root access. This
update strips the setgid bit from /usr/bin/gpg.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:053-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg package";
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
if ( rpm_check( reference:"gnupg-1.0.6-2.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.0.6-2.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.0.6-2.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.0.6-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
