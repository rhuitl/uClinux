#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12479);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0851", "CVE-2004-0081");

 name["english"] = "RHSA-2004-119: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages that fix a remote denial of service vulnerability
  are now available for Red Hat Enterprise Linux 2.1.

  OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3) and
  Transport Layer Security (TLS v1) protocols as well as a full-strength
  general purpose cryptography library.

  Testing performed by the OpenSSL group using the Codenomicon TLS Test Tool
  uncovered a bug in older versions of OpenSSL 0.9.6 prior to 0.9.6d that can
  lead to a denial of service attack (infinite loop). The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0081 to this issue.

  Testing performed by Novell using a test suite provided by NISCC uncovered
  an issue in the ASN.1 parser in versions of OpenSSL 0.9.6 prior to 0.9.6l
  which could cause large recursion and possibly lead to a denial of service
  attack if used where stack space is limited. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2003-0851
  to this issue.

  These updated packages contain patches provided by the OpenSSL group that
  protect against these issues.

  NOTE: Because server applications are affected by this issue, users are
  advised to either restart all services using OpenSSL functionality or
  restart their system after installing these updated packages.




Solution : http://rhn.redhat.com/errata/RHSA-2004-119.html
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
if ( rpm_check( reference:"openssl-0.9.6b-36", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-36", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-36", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-24", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-25.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0851", value:TRUE);
 set_kb_item(name:"CVE-2004-0081", value:TRUE);
}

set_kb_item(name:"RHSA-2004-119", value:TRUE);
