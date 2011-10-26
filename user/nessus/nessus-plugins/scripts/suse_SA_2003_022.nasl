#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:022
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13792);
 script_bugtraq_id(7200);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0098", "CVE-2003-0099");
 
 name["english"] = "SUSE-SA:2003:022: apcupsd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:022 (apcupsd).


The controlling and management daemon apcupsd for APC's Unbreakable
Power Supplies is vulnerable to several buffer overflows and format
bugs. These bugs can be exploited remotely by an attacker to gain
root access to the machine apcupsd is running on.

There is no temporary fix known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_022_apcupsd.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apcupsd package";
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
if ( rpm_check( reference:"apcupsd-3.8.2-70", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apcupsd-3.8.6-16", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apcupsd-3.8.6-17", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"apcupsd-", release:"SUSE7.3")
 || rpm_exists(rpm:"apcupsd-", release:"SUSE8.0")
 || rpm_exists(rpm:"apcupsd-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0098", value:TRUE);
 set_kb_item(name:"CVE-2003-0099", value:TRUE);
}
