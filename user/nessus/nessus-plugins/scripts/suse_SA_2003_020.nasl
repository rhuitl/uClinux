#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:020
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13790);
 script_bugtraq_id(7120);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0140");
 
 name["english"] = "SUSE-SA:2003:020: mutt";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:020 (mutt).


Mutt is a text-based Mail User Agent (MUA).
The IMAP-code of mutt is vulnerable to a buffer overflow that can be
exploited by a malicious IMAP-server to crash mutt or even execute
arbitrary code with the privileges of the user running mutt.

There is no temporary fix known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_020_mutt.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mutt package";
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
if ( rpm_check( reference:"mutt-1.3.12i-69", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.3.16i-92", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.3.22.1i-170", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.3.27i-77", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.4i-216", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"mutt-", release:"SUSE7.1")
 || rpm_exists(rpm:"mutt-", release:"SUSE7.2")
 || rpm_exists(rpm:"mutt-", release:"SUSE7.3")
 || rpm_exists(rpm:"mutt-", release:"SUSE8.0")
 || rpm_exists(rpm:"mutt-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0140", value:TRUE);
}
