#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12368);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0078");

 name["english"] = "RHSA-2003-063: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages are available that fix a potential timing-based
  attack.

  [Updated 12 March 2003]
  Added packages for Red Hat Enterprise Linux ES and Red Hat Enterprise
  Linux WS

  OpenSSL is a commercial-grade, full-featured, open source toolkit which
  implements the Secure Sockets Layer (SSL v2/v3) and Transport Layer
  Security (TLS v1) protocols as well as a full-strength, general purpose
  cryptography library.

  In a paper, Brice Canvel, Alain Hiltgen, Serge Vaudenay, and Martin
  Vuagnoux describe and demonstrate a timing-based attack on CBC ciphersuites
  in SSL and TLS. An active attacker may be able to use timing observations
  to distinguish between two different error cases: cipher padding errors and
  MAC verification errors. Over multiple connections this can leak
  sufficient information to be able to retrieve the plaintext of a common,
  fixed block.

  In order for an attack to be sucessful an attacker must be able to act as a
  man-in-the-middle to intercept and modify multiple connections which all
  involve a common fixed plaintext block (such as a password), and have good
  network conditions that allow small changes in timing to be reliably
  observed.

  These updated packages contain a patch provided by the OpenSSL group that
  corrects this vulnerability.

  Because server applications are affected by these vulnerabilities, we
  advise users to restart all services that use OpenSSL functionality or
  alternatively reboot their systems after installing these updates.




Solution : http://rhn.redhat.com/errata/RHSA-2003-063.html
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
if ( rpm_check( reference:"openssl-0.9.6b-30.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-30.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-30.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-18.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-13.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0078", value:TRUE);
}

set_kb_item(name:"RHSA-2003-063", value:TRUE);
