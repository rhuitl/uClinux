#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:019
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13789);
 script_bugtraq_id(7049);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0081");
 
 name["english"] = "SUSE-SA:2003:019: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:019 (ethereal).


Ethereal is a GUI for analyzing and displaying network traffic.
Ethereal is vulnerable to a format string bug in it's SOCKS code
and to a heap buffer overflow in it's NTLMSSP code.
These bugs can be abused to crash ethereal or maybe to execute
arbitrary code on the machine running ethereal.

There is no temporary workaround known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_019_ethereal.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.9.6-156", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.6-155", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.6-154", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.6-153", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.6-152", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"SUSE7.1")
 || rpm_exists(rpm:"ethereal-", release:"SUSE7.2")
 || rpm_exists(rpm:"ethereal-", release:"SUSE7.3")
 || rpm_exists(rpm:"ethereal-", release:"SUSE8.0")
 || rpm_exists(rpm:"ethereal-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0081", value:TRUE);
}
