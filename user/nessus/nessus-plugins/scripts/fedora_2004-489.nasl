#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15896);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1013", "CVE-2004-1015");
 
 name["english"] = "Fedora Core 2 2004-489: cyrus-imapd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-489 (cyrus-imapd).

The cyrus-imapd package contains the core of the Cyrus IMAP server.
It is a scaleable enterprise mail system designed for use from
small to large enterprise environments using standards-based
internet mail technologies.

A full Cyrus IMAP implementation allows a seamless mail and bulletin
board environment to be set up across multiple servers. It differs
from
other IMAP server implementations in that it is run on 'sealed'
servers, where users are not normally permitted to log in. The mailbox
database is stored in parts of the filesystem that are private to the
Cyrus IMAP server. All user access to mail is through software using
the IMAP, POP3, or KPOP protocols. TLSv1 and SSL are supported for
security.

Update Information:

Fix several buffer overflow problems that could be used as an exploit.
Fixes the following security advisories:
CVE-2004-1011 CVE-2004-1012 CVE-2004-1013 CVE-2004-1015


Solution : http://www.fedoranews.org/blog/index.php?p=148
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-imapd package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cyrus-imapd-2.2.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-murder-2.2.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-nntp-2.2.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.2.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-2.2.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-utils-2.2.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"cyrus-imapd-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-1013", value:TRUE);
 set_kb_item(name:"CVE-2004-1015", value:TRUE);
}
