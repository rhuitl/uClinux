#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22331);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4339");

 name["english"] = "RHSA-2006-0661: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages are now available to correct a security issue.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The OpenSSL toolkit provides support for secure communications between
  machines. OpenSSL includes a certificate management tool and shared
  libraries which provide various cryptographic algorithms and protocols.

  Daniel Bleichenbacher recently described an attack on PKCS #1 v1.5
  signatures. Where an RSA key with exponent 3 is used it may be possible
  for an attacker to forge a PKCS #1 v1.5 signature that would be incorrectly
  verified by implementations that do not check for excess data in the RSA
  exponentiation result of the signature.

  The Google Security Team discovered that OpenSSL is vulnerable to this
  attack. This issue affects applications that use OpenSSL to verify X.509
  certificates as well as other uses of PKCS #1 v1.5. (CVE-2006-4339)

  This errata also resolves a problem where a customized ca-bundle.crt file
  was overwritten when the openssl package was upgraded.

  Users are advised to upgrade to these updated packages, which contain a
  backported patch to correct this issue.

  Note: After installing this update, users are advised to either restart all
  services that use OpenSSL or restart their system.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0661.html
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
if ( rpm_check( reference:"openssl-0.9.6b-43", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  openssl-0.9.6b-43.i686.rpm                 44e1a5814a8585403858e7b0efd459e9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-43", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-43", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-29", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-29", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-33.18", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  openssl-0.9.7a-33.18.i686.rpm              ac5c706e41e44d719eed51f218b14713", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-33.18", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-33.18", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-16.43", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-43.11", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  openssl-0.9.7a-43.11.i686.rpm              68435a368c5e4a16bea0e9490071e4e6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-43.11", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-43.11", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-22.43", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-4339", value:TRUE);
}
if ( rpm_exists(rpm:"openssl-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-4339", value:TRUE);
}
if ( rpm_exists(rpm:"openssl-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4339", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0661", value:TRUE);
