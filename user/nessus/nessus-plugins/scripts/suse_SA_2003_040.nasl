#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:040
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13808);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0005");
 script_bugtraq_id(8641);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2003-0694");
 
 name["english"] = "SUSE-SA:2003:040: sendmail, sendmail-tls";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:040 (sendmail, sendmail-tls).


sendmail is the most widely used mail transport agent (MTA) in the
internet. A remotely exploitable buffer overflow has been found in all
versions of sendmail that come with SUSE products. These versions include
sendmail-8.11 and sendmail-8.12 releases. sendmail is the MTA subsystem
that is installed by default on all SUSE products up to and including
SUSE LINUX 8.0 and the SUSE LINUX Enterprise Server 7.

The vulnerability discovered is known as the prescan()-bug and is not
related to the vulnerability found and fixed in April 2003. The error
in the code can cause heap or stack memory to be overwritten, triggered
by (but not limited to) functions that parse header addresses. 

There is no known workaround for this vulnerability other than using a
different MTA. The vulnerability is triggered by an email message sent
through the sendmail MTA subsystem. In that respect, it is different
from commonly known bugs that occur in the context of an open TCP
connection. By consequence, the vulnerability also exists if email
messages get forwarded over a relay that itself does not run a vulnerable
MTA. This specific detail and the wide distribution of sendmail in the
internet causes this vulnerability to be considered a flaw of major
severity. We recommend to install the update packages that are provided
for download at the locations listed below.

We thank Michal Zalewski who discovered this vulnerability and the 
friendly people from Sendmail Inc (Claus Assmann) who have communicated
problem to SUSE Security.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_040_sendmail.html
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
if ( rpm_check( reference:"sendmail-8.11.3-112", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.3-116", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.6-167", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.6-169", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.3-78", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.3-78", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-159", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.6-159", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.7-77", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.7-77", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sendmail-", release:"SUSE7.2")
 || rpm_exists(rpm:"sendmail-", release:"SUSE7.3")
 || rpm_exists(rpm:"sendmail-", release:"SUSE8.0")
 || rpm_exists(rpm:"sendmail-", release:"SUSE8.1")
 || rpm_exists(rpm:"sendmail-", release:"SUSE8.2") )
{
 set_kb_item(name:"CVE-2003-0694", value:TRUE);
}
