#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18409);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0975", "CVE-2005-0109");

 name["english"] = "RHSA-2005-476: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL packages that fix security issues are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3) and
  Transport Layer Security (TLS v1) protocols as well as a full-strength
  general purpose cryptography library.



Solution : http://rhn.redhat.com/errata/RHSA-2005-476.html
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
if ( rpm_check( reference:"openssl-0.9.6b-39", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-39", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-39", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-25", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-25.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-33.15", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-33.15", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-33.15", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-16.22.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-43.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-43.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-43.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-22.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0975", value:TRUE);
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
}
if ( rpm_exists(rpm:"openssl-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0975", value:TRUE);
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
}
if ( rpm_exists(rpm:"openssl-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-0975", value:TRUE);
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
}

set_kb_item(name:"RHSA-2005-476", value:TRUE);
