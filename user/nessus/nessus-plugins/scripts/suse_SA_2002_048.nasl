#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:048
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13769);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2002:048: cyrus-imapd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:048 (cyrus-imapd).


The cyrus imapd contains a buffer overflow which could be exploited
by remote attackers prior to logging in. Attackers could generate oversized
error messages and overflow buffers inside imapd.
Additionally to this fix, an overflow in the SASL library (as used by the
cyrus imapd) has been fixed. This bug only affects SUSE LINUX 8.1, the
SUSE LINUX Enterprise Server 8 and the SUSE LINUX Openexchange Server.

Since there is no workaround possible except shutting down the IMAP server,
we strongly recommend an update.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_048_cyrus_imapd.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-imapd package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cyrus-imapd-2.0.12-69", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.0.16-362", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.0.16-361", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.0.16-361", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.1.9-41", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl2-2.1.7-52", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
