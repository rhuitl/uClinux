#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12480);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0079", "CVE-2004-0081", "CVE-2004-0112");

 name["english"] = "RHSA-2004-120: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages that fix several remote denial of service
  vulnerabilities are available for Red Hat Enterprise Linux 3.

  The OpenSSL toolkit implements Secure Sockets Layer (SSL v2/v3),
  Transport Layer Security (TLS v1) protocols, and serves as a full-strength
  general purpose cryptography library.

  Testing performed by the OpenSSL group using the Codenomicon TLS Test Tool
  uncovered a null-pointer assignment in the do_change_cipher_spec() function
  in OpenSSL 0.9.6c-0.9.6k and 0.9.7a-0.9.7c. A remote attacker could
  perform a carefully crafted SSL/TLS handshake against a server that uses
  the OpenSSL library in such a way as to cause OpenSSL to crash. Depending
  on the application this could lead to a denial of service. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0079 to this issue.

  Stephen Henson discovered a flaw in SSL/TLS handshaking code when using
  Kerberos ciphersuites in OpenSSL 0.9.7a-0.9.7c. A remote attacker could
  perform a carefully crafted SSL/TLS handshake against a server configured
  to use Kerberos ciphersuites in such a way as to cause OpenSSL to crash.
  Most applications have no ability to use Kerberos ciphersuites and will
  therefore be unaffected by this issue. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0112 to
  this issue.

  Testing performed by the OpenSSL group using the Codenomicon TLS Test Tool
  uncovered a bug in older versions of OpenSSL 0.9.6 prior to 0.9.6d that may
  lead to a denial of service attack (infinite loop). The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0081 to this issue. This issue affects only the OpenSSL
  compatibility packages shipped with Red Hat Enterprise Linux 3.

  These updated packages contain patches provided by the OpenSSL group that
  protect against these issues.

  Additionally, the version of libica included in the OpenSSL packages has
  been updated to 1.3.5. This only affects IBM s390 and IBM eServer zSeries
  customers and is required for the latest openCryptoki packages.

  NOTE: Because server applications are affected by this issue, users are
  advised to either restart all services that use OpenSSL functionality or
  restart their systems after installing these updates.




Solution : http://rhn.redhat.com/errata/RHSA-2004-120.html
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
if ( rpm_check( reference:"openssl-0.9.7a-33.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-33.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-33.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-16", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0079", value:TRUE);
 set_kb_item(name:"CVE-2004-0081", value:TRUE);
 set_kb_item(name:"CVE-2004-0112", value:TRUE);
}

set_kb_item(name:"RHSA-2004-120", value:TRUE);
