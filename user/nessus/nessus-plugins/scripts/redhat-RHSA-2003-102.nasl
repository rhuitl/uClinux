#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12380);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0131", "CVE-2003-0147");

 name["english"] = "RHSA-2003-102: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages are available that fix a potential timing-based
  attack and a modified Bleichenbacher attack.

  [Updated 30 May 2003]
  Added missing i686 packages.

  OpenSSL is a commercial-grade, full-featured, open source toolkit that
  implements the Secure Sockets Layer (SSL v2/v3) and Transport Layer
  Security (TLS v1) protocols, and provides a full-strength general purpose
  cryptography library.

  Researchers discovered a timing attack on RSA keys. Applications making
  use of OpenSSL are generally vulnerable to such an attack, unless RSA
  blinding has been turned on. OpenSSL does not use RSA blinding by default
  and most applications do not enable RSA blinding.

  A local or remote attacker could use this attack to obtain the server\'s
  private key by determining factors using timing differences on (1) the
  number of extra reductions during Montgomery reduction, and (2) the use of
  different integer multiplication algorithms (Karatsuba and normal).

  In order for an attack to be sucessful, an attacker must have good
  network conditions that allow small changes in timing to be reliably
  observed.

  Additionally, the SSL and TLS components for OpenSSL allow remote attackers
  to perform an unauthorized RSA private key operation via a modified
  Bleichenbacher attack. This attack (also known as the Klima-Pokorny-Rosa
  attack) uses a large number of SSL or TLS connections using PKCS #1 v1.5
  padding to cause OpenSSL to leak information regarding the relationship
  between ciphertext and the associated plaintext.

  These erratum packages contain a patch provided by the OpenSSL group that
  enables RSA blinding by default, and protects against the
  Klima-Pokorny-Rosa attack.

  Because server applications are affected by these vulnerabilities, we
  advise users to restart all services that use OpenSSL functionality or,
  alternatively, reboot their systems after installing these updates.




Solution : http://rhn.redhat.com/errata/RHSA-2003-102.html
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
if ( rpm_check( reference:"openssl-0.9.6b-32.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-32.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-32.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-20.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-16.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0131", value:TRUE);
 set_kb_item(name:"CVE-2003-0147", value:TRUE);
}

set_kb_item(name:"RHSA-2003-102", value:TRUE);
