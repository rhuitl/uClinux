#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22472);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");

 name["english"] = "RHSA-2006-0695: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages are now available to correct several security
  issues.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The OpenSSL toolkit provides support for secure communications between
  machines. OpenSSL includes a certificate management tool and shared
  libraries which provide various cryptographic algorithms and protocols.

  Tavis Ormandy and Will Drewry of the Google Security Team discovered a
  buffer overflow in the SSL_get_shared_ciphers() utility function. An
  attacker could send a list of ciphers to an application that used this
  function and overrun a buffer (CVE-2006-3738). Few applications make use
  of this vulnerable function and generally it is used only when applications
  are compiled for debugging.

  Tavis Ormandy and Will Drewry of the Google Security Team discovered a
  flaw in the SSLv2 client code. When a client application used OpenSSL to
  create an SSLv2 connection to a malicious server, that server could cause
  the client to crash. (CVE-2006-4343)

  Dr S. N. Henson of the OpenSSL core team and Open Network Security recently
  developed an ASN.1 test suite for NISCC (www.niscc.gov.uk) which uncovered
  denial of service vulnerabilities:

  * Certain public key types can take disproportionate amounts of time to
  process, leading to a denial of service. (CVE-2006-2940)

  * During parsing of certain invalid ASN.1 structures an error condition was
  mishandled. This can result in an infinite loop which consumed system
  memory (CVE-2006-2937). This issue does not affect the OpenSSL version
  distributed in Red Hat Enterprise Linux 2.1.

  These vulnerabilities can affect applications which use OpenSSL to parse
  ASN.1 data from untrusted sources, including SSL servers which enable
  client authentication and S/MIME applications.

  Users are advised to upgrade to these updated packages, which contain
  backported patches to correct these issues.

  Note: After installing this update, users are advised to either restart all
  services that use OpenSSL or restart their system.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0695.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssl-0.9.6b-46", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  openssl-0.9.6b-46.i686.rpm                 fca94acfb677dc9155716d7a779f7ede", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-46", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-46", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-32", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-32", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-33.21", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  openssl-0.9.7a-33.21.i686.rpm              0ddbef7542c03a39e5b783befa49faf9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-33.21", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-33.21", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-16.46", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-43.14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  openssl-0.9.7a-43.14.i686.rpm              f2b76677a5e6cc4d2a55e78eb56a4fdb", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-43.14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-43.14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-22.46", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-2937", value:TRUE);
 set_kb_item(name:"CVE-2006-2940", value:TRUE);
 set_kb_item(name:"CVE-2006-3738", value:TRUE);
 set_kb_item(name:"CVE-2006-4343", value:TRUE);
}
if ( rpm_exists(rpm:"openssl-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-2937", value:TRUE);
 set_kb_item(name:"CVE-2006-2940", value:TRUE);
 set_kb_item(name:"CVE-2006-3738", value:TRUE);
 set_kb_item(name:"CVE-2006-4343", value:TRUE);
}
if ( rpm_exists(rpm:"openssl-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-2937", value:TRUE);
 set_kb_item(name:"CVE-2006-2940", value:TRUE);
 set_kb_item(name:"CVE-2006-3738", value:TRUE);
 set_kb_item(name:"CVE-2006-4343", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0695", value:TRUE);
