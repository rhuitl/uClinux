#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:034
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13940);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:034: imap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:034 (imap).


A buffer overflow was discovered in the imap server that could allow a malicious
user to run code on the server with the uid and gid of the email owner by
constructing a malformed request that would trigger the buffer overflow.
However, the user must successfully authenticate to the imap service in order to
exploit it, which limits the scope of the vulnerability somewhat, unless you are
a free mail provider or run a mail service where users do not already have shell
access to the system.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:034
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
if ( rpm_check( reference:"imap-2000c-4.9mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2000c-4.9mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2000c-4.8mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2000c-4.8mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2000c-4.7mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2000c-4.7mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2000c-7.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2000c-7.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2001a-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2001a-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
