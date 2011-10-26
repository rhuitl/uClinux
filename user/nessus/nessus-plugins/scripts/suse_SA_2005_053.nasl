#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:053
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19932);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:053: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:053 (squid).


This update of the Squid web-proxy fixes two remotely exploitable denial
of service vulnerabilities.

One can be triggered by aborting a request (CVE-2005-2794) due to a faulty
assertion.

The other one occurs in sslConnectTimeout while handling malformated
requests (CVE-2005-2796).

The latter one does not affect SUSE LINUX 9.3.

2) Solution or Workaround

There are no workarounds known.

3) Special Instructions and Notes

Please restart the Squid web-proxy after the update.

4) Package Location and Checksums

The preferred method for installing security updates is to use the YaST
Online Update (YOU) tool. YOU detects which updates are required and
automatically performs the necessary steps to verify and install them.
Alternatively, download the update packages for your distribution manually
and verify their integrity by the methods listed in Section 6 of this
announcement. Then install the packages using the command

rpm -Fhv <file.rpm>

to apply the update, replacing <file.rpm> with the filename of the
downloaded RPM package.


Solution : http://www.suse.de/security/advisories/2005_53_squid.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"squid-2.5.STABLE3-126", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE5-42.41", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE6-6.15", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE9-4.4", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
