#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:033
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13802);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0468", "CVE-2003-0540");
 
 name["english"] = "SUSE-SA:2003:033: postfix";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:033 (postfix).


Postfix is a flexible MTA replacement for sendmail.
Michal Zalewski has reported problems in postfix which can lead to
a remote DoS attack or allow attackers to bounce-scan private networks.
These problems have been fixed. Even though not all of our products are
vulnerable in their default configurations, the updates should be applied.

In order for the update to take effect, you have to restart your MTA
by issuing the following command as root:

'/sbin/rcpostfix restart'


Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_033_postfix.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postfix package";
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
if ( rpm_check( reference:"postfix-20010228pl03-82", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postfix-20010228pl08-22", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postfix-1.1.12-13", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postfix-1.1.12-12", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"postfix-", release:"SUSE7.2")
 || rpm_exists(rpm:"postfix-", release:"SUSE7.3")
 || rpm_exists(rpm:"postfix-", release:"SUSE8.0")
 || rpm_exists(rpm:"postfix-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0468", value:TRUE);
 set_kb_item(name:"CVE-2003-0540", value:TRUE);
}
