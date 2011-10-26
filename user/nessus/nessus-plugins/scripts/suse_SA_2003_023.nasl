#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:023
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13793);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2003:023: sendmail, sendmail-tls";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:023 (sendmail, sendmail-tls).


sendmail is the most widely used mail transport agent (MTA) in the
internet. A remotely exploitable buffer overflow has been found in all
versions of sendmail that come with SUSE products. These versions include
sendmail-8.11 and sendmail-8.12 releases. sendmail is the MTA subsystem
that is installed by default on all SUSE products up to and including
SUSE LINUX 8.0 and the SUSE LINUX Enterprise Server 7.

The vulnerability was discovered by Michal Zalewski. It is not related
to the vulnerability found by ISS in the first week of March as announced

Solution : http://www.suse.de/security/2003_023_sendmail.html
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
if ( rpm_check( reference:"sendmail-8.11.2-45", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.2-47", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.3-108", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.3-112", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.6-164", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.6-166", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.3-75", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-109", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
