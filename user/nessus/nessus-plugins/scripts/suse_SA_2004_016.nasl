#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:016
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13832);
 script_bugtraq_id(10500);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0541");
 
 name["english"] = "SuSE-SA:2004:016: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2004:016 (squid).


Squid is a feature-rich web-proxy with support for various web-related
protocols.
The NTLM authentication helper application of Squid is vulnerable to
a buffer overflow that can be exploited remotely by using a long
password to execute arbitrary code.
NTLM authentication is enabled by default in the Squid package that
is shipped by SUSE LINUX.

There is no workaround known other then turning off the NTLM
authentication.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2004_16_squid.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.4.STABLE6-9", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE1-98", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-110", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE5-42.9", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"SUSE8.0")
 || rpm_exists(rpm:"squid-", release:"SUSE8.2")
 || rpm_exists(rpm:"squid-", release:"SUSE9.0")
 || rpm_exists(rpm:"squid-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0541", value:TRUE);
}
