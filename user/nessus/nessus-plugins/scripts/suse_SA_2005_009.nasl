#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:009
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17217);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:009: cyrus-imapd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:009 (cyrus-imapd).


This update fixes one-byte buffer overruns in the cyrus-imapd IMAP
server package.

Several overruns were fixed in the IMAP annote extension as well as
in cached header handling which can be run by an authenticated user.

Additionally bounds checking in fetchnews was improved to avoid
exploitation by a peer news admin.

Please note that one-byte buffer overflows can not be exploited to
execute arbitrary commands by manipulating the saved registers on
the stack if the compiler used (gcc >= 3) aligns the stack space.

Nevertheless the code behavior may be manipulated by overwriting
local variables. The result is not known but ranges between a
denial-of-service condition and privilege escalation.

This update backports bugfixes from the upstream release of
cyrus-imapd 2.2.11 announced on:

http://asg.web.cmu.edu/archive/message.php?mailbox=archive.info-cyrus&msg=33723


Solution : http://www.suse.de/security/advisories/2005_09_cyrus_imapd.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-imapd package";
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
if ( rpm_check( reference:"cyrus-imapd-2.1.12-77", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.1.15-91", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.2.3-83.22", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.2.8-6.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
