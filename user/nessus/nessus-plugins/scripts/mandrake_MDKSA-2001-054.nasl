#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:054
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13871);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:054: imap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:054 (imap).


Several buffer overflow vulnerabilities have been found in the UW-IMAP package
by the authors and independant groups. These vulnerabilities can be exploited
only once a user has authenticated which limits the extent of the vulnerability
to a remote shell with that user's permissions. On systems where the user
already has a shell, nothing new will be provided to that user, unless the user
has only local shell access. On systems where the email accounts do not provide
shell access, however, the problem is much greater.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:054
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imap package";
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
if ( rpm_check( reference:"imap-2000c-4.6mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2000c-4.6mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2000c-4.5mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2000c-4.5mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2000c-4.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2000c-4.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
