#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:026
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16292);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2005:026: imap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:026 (imap).



A vulnerability was discovered in the CRAM-MD5 authentication in UW-IMAP where,
on the fourth failed authentication attempt, a user would be able to access the
IMAP server regardless. This problem exists only if you are using CRAM-MD5
authentication and have an /etc/cram-md5.pwd file. This is not the default
setup.

The updated packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:026
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imap package";
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
if ( rpm_check( reference:"imap-2002d-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2002d-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-utils-2002d-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2004-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2004-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-utils-2004-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libc-client-php0-2004-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libc-client-php0-devel-2004-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
