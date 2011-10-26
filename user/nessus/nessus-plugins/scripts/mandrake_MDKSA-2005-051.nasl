#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:051
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17280);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2005:051: cyrus-imapd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:051 (cyrus-imapd).



Several overruns have been fixed in the IMAP annote extension as well as in
cached header handling which can be run by an authenticated user. As well,
additional bounds checking in fetchnews was improved to avoid exploitation by a
peer news admin.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:051
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-imapd package";
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
if ( rpm_check( reference:"cyrus-imapd-2.1.16-5.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.1.16-5.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-murder-2.1.16-5.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-utils-2.1.16-5.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-2.1.16-5.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.2.8-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.2.8-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-murder-2.2.8-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-nntp-2.2.8-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-utils-2.2.8-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-2.2.8-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
