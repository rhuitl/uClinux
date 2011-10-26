#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20050);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0109", "CVE-2005-2969");

 name["english"] = "RHSA-2005-800: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages that fix various security issues are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3) and
  Transport Layer Security (TLS v1) protocols as well as a full-strength
  general purpose cryptography library.

  OpenSSL contained a software work-around for a bug in SSL handling in
  Microsoft Internet Explorer version 3.0.2. This work-around is enabled in
  most servers that use OpenSSL to provide support for SSL and TLS. Yutaka
  Oiwa discovered that this work-around could allow an attacker, acting as a
  "man in the middle" to force an SSL connection to use SSL 2.0 rather than a
  stronger protocol such as SSL 3.0 or TLS 1.0. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2005-2969
  to this issue.

  A bug was also fixed in the way OpenSSL creates DSA signatures. A cache
  timing attack was fixed in RHSA-2005-476 which caused OpenSSL to do private
  key calculations with a fixed time window. The DSA fix for this was not
  complete and the calculations are not always performed within a
  fixed-window. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0109 to this issue.

  Users are advised to upgrade to these updated packages, which remove the
  MISE 3.0.2 work-around and contain patches to correct these issues.

  Note: After installing this update, users are advised to either
  restart all services that use OpenSSL or restart their system.




Solution : http://rhn.redhat.com/errata/RHSA-2005-800.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssl-0.9.6b-40", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-40", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-40", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-26", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-27", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-33.17", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-33.17", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-33.17", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-16.22.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-43.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-43.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-43.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-22.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
 set_kb_item(name:"CVE-2005-2969", value:TRUE);
}
if ( rpm_exists(rpm:"openssl-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
 set_kb_item(name:"CVE-2005-2969", value:TRUE);
}
if ( rpm_exists(rpm:"openssl-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
 set_kb_item(name:"CVE-2005-2969", value:TRUE);
}

set_kb_item(name:"RHSA-2005-800", value:TRUE);
