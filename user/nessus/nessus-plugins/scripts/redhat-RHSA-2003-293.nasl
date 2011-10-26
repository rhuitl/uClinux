#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12425);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0543", "CVE-2003-0544");

 name["english"] = "RHSA-2003-293: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages are available that fix ASN.1 parsing
  vulnerabilities.

  OpenSSL is a commercial-grade, full-featured, and open source toolkit that
  implements Secure Sockets Layer (SSL v2/v3) and Transport Layer Security
  (TLS v1) protocols as well as a full-strength general purpose cryptography
  library.

  NISCC testing of implementations of the SSL protocol uncovered two bugs in
  OpenSSL 0.9.6. The parsing of unusual ASN.1 tag values can cause OpenSSL to
  crash. A remote attacker could trigger this bug by sending a carefully
  crafted SSL client certificate to an application. The effects of such an
  attack vary depending on the application targetted; against Apache the
  effects are limited, as the attack would only cause child processes to die
  and be replaced. An attack against other applications that use OpenSSL
  could result in a Denial of Service. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CVE-2003-0543 and
  CVE-2003-0544 to this issue.

  These erratum packages contain a patch provided by the OpenSSL group that
  protects against this issue.

  Because server applications are affected by this issue, users are advised
  to either restart all services that use OpenSSL functionality or reboot
  their systems after installing these updates.

  Red Hat would like to thank NISCC and Stephen Henson for their work on this
  vulnerability.

  These packages also include a patch from OpenSSL 0.9.6f which removes
  the calls to abort the process in certain circumstances. Red Hat would
  like to thank Patrik Hornik for notifying us of this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-293.html
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
if ( rpm_check( reference:"openssl-0.9.6b-35.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-35.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-35.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-23.7.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-23.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0543", value:TRUE);
 set_kb_item(name:"CVE-2003-0544", value:TRUE);
}

set_kb_item(name:"RHSA-2003-293", value:TRUE);
