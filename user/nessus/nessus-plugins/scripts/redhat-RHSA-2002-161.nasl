#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12316);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0659");

 name["english"] = "RHSA-2002-161: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages are available for Red Hat Linux Advanced Server.
  These updates fix multiple protocol parsing bugs, which may cause a denial
  of service (DoS) attack or cause SSL-enabled applications to crash.

  [Updated 06 Jan 2003]
  Added fixed packages for the ia64 architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  OpenSSL is a commercial-grade, full-featured, and open source toolkit
  which implements the Secure Sockets Layer (SSL v2/v3) and Transport Layer
  Security (TLS v1) protocols as well as a full-strength general purpose
  cryptography library.

  Portions of the SSL protocol data stream, which include the lengths of
  structures which are being transferred, may not be properly validated.
  This may allow a malicious server or client to cause an affected
  application to crash or enter an infinite loop, which can be used as a
  denial of service (DoS) attack if the application is a server. It has not
  been verified if this issue could lead to further consequences such as
  remote code execution.

  These errata packages contain a patch to correct this vulnerability.
  Please note that the original patch from the OpenSSL team had a mistake in
  it which could possibly still allow buffer overflows to occur. This bug
  is also fixed in these errata packages.

  NOTE:

  Please read the Solution section below as it contains instructions for
  making sure that all SSL-enabled processes are restarted after the update
  is applied.

  Thanks go to the OpenSSL team for providing patches for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2002-161.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssl-0.9.6b-28", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-28", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-28", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-18", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-13", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0659", value:TRUE);
}

set_kb_item(name:"RHSA-2002-161", value:TRUE);
