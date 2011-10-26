#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22360);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4790");

 name["english"] = "RHSA-2006-0680: gnutls";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gnutls packages that fix a security issue are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The GnuTLS Library provides support for cryptographic algorithms and
  protocols such as TLS. GnuTLS includes libtasn1, a library developed for
  ASN.1 structures management that includes DER encoding and decoding.

  Daniel Bleichenbacher recently described an attack on PKCS #1 v1.5
  signatures. Where an RSA key with exponent 3 is used it may be possible for
  an attacker to forge a PKCS #1 v1.5 signature that would be incorrectly
  verified by implementations that do not check for excess data in the RSA
  exponentiation result of the signature.

  The core GnuTLS team discovered that GnuTLS is vulnerable to a variant of
  the Bleichenbacker attack. This issue affects applications that use GnuTLS
  to verify X.509 certificates as well as other uses of PKCS #1 v1.5.
  (CVE-2006-4790)

  In Red Hat Enterprise Linux 4, the GnuTLS library is only used by the
  Evolution client when connecting to an Exchange server or when publishing
  calendar information to a WebDAV server.

  Users are advised to upgrade to these updated packages, which contain a
  backported patch from the GnuTLS maintainers to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0680.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnutls packages";
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
if ( rpm_check( reference:"gnutls-1.0.20-3.2.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnutls-devel-1.0.20-3.2.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gnutls-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4790", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0680", value:TRUE);
