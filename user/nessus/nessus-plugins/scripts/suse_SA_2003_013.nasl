#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:013
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13784);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2003:013: sendmail, sendmail-tls";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:013 (sendmail, sendmail-tls).


sendmail is the most widely used mail transport agent (MTA) in the
internet. A remotely exploitable buffer overflow has been found in all
versions of sendmail that come with SUSE products. These versions include
sendmail-8.11 and sendmail-8.12 releases. sendmail is the MTA subsystem
that is installed by default on all SUSE products up to and including
SUSE LINUX 8.0 and the SUSE LINUX Enterprise Server 7.

The vulnerability is triggered by an email message sent through the
sendmail MTA subsystem. In that respect, it is different from commonly
known bugs that occur in the context of an open TCP connection. By
consequence, the vulnerability also exists if email messages get forwarded
over a relay that itself does not run a vulnerable MTA. This specific
detail and the wide distribution of sendmail in the internet causes this
vulnerability to be considered an error of major severity.

The buffer overflow happens on the heap and is known to be exploitable.
As of the writing of this announcement, there is no exploit known to exist
in the public. Since there is no known workaround for this vulnerability
other than using a different MTA, it is strongly recommended to install
the update packages as offered at the locations as listed below.

We would like to express our gratitude to Eric Allman for notifying
SUSE Security of the problem. The vulnerability was discovered by
ISS Internet Security Systems, inc.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_13_sendmail.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail, sendmail-tls package";
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
if ( rpm_check( reference:"sendmail-8.11.2-44", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.2-45", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.3-106", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.3-110", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.6-162", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.6-164", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.3-72", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.3-72", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-91", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.6-91", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
