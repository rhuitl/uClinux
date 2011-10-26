#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:012
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13829);
 script_bugtraq_id(10242);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0226", "CVE-2004-0231", "CVE-2004-0232");
 
 name["english"] = "SuSE-SA:2004:012: mc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2004:012 (mc).


The Midnight Commander (mc) is a file manager for the console.
The mc code is vulnerable to several security related bugs like buffer
overflows, incorrect format string handling and insecure usage of
temporary files.
These bugs can be exploited by local users to gain access to the
privileges of the user running mc.

There is no workaround known other then avoid using mc.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2004_12_mc.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mc package";
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
if ( rpm_check( reference:"mc-4.5.55-758", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mc-4.5.55-758", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mc-4.6.0-327", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mc-4.6.0-327", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"mc-", release:"SUSE8.0")
 || rpm_exists(rpm:"mc-", release:"SUSE8.1")
 || rpm_exists(rpm:"mc-", release:"SUSE8.2")
 || rpm_exists(rpm:"mc-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2004-0226", value:TRUE);
 set_kb_item(name:"CVE-2004-0231", value:TRUE);
 set_kb_item(name:"CVE-2004-0232", value:TRUE);
}
