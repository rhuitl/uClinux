#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:035
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13756);
 script_bugtraq_id(5349);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2002-1050");
 
 name["english"] = "SUSE-SA:2002:035: hylafax";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:035 (hylafax).


HylaFAX is a client-server architecture for receiving and sending
facsimiles.

The logging function of faxgetty prior version 4.1.3 was vulnerable to
a format string bug when handling the TSI value of a received facsimile.
This bug could easily be used to trigger a denial-of-service attack or
to execute arbitrary code remotely.

Another bug in faxgetty, a buffer overflow, can be abused by a remote
attacker by sending a large line of image data to execute arbitrary
commands too.

Several format string bugs in local helper applications were fixed too.
These bugs can not be exploited to gain higher privileges on a system
running SUSE LINUX because of the absence of setuid bits.

The hylafax package is not installed by default.
A temporary fix is not known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_035_hylafax.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the hylafax package";
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
if ( rpm_check( reference:"hylafax-4.1beta2-373", release:"SUSE7.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1beta2-375", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1beta2-376", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1-284", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1-285", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"hylafax-", release:"SUSE7.0")
 || rpm_exists(rpm:"hylafax-", release:"SUSE7.1")
 || rpm_exists(rpm:"hylafax-", release:"SUSE7.2")
 || rpm_exists(rpm:"hylafax-", release:"SUSE7.3")
 || rpm_exists(rpm:"hylafax-", release:"SUSE8.0") )
{
 set_kb_item(name:"CVE-2002-1050", value:TRUE);
}
