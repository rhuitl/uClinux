#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16222);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1018", "CVE-2004-1019");

 name["english"] = "RHSA-2005-031: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated php packages that fix various security issues are now
  available for Red Hat Enterprise Linux 2.1.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  A double-free bug was found in the deserialization code of PHP. PHP
  applications use the unserialize function on untrusted user data, which
  could allow a remote attacker to gain access to memory or potentially
  execute arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-1019 to this issue.

  Flaws were found in the pack and unpack PHP functions. These functions
  do not normally pass user supplied data, so they would require a malicious
  PHP script to be exploited. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-1018 to this issue.

  A bug was discovered in the initialization of the OpenSSL library, such
  that the curl extension could not be used to perform HTTP requests over SSL
  unless the php-imap package was installed.

  Users of PHP should upgrade to these updated packages, which contain fixes
  for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-031.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php packages";
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
if ( rpm_check( reference:"php-4.1.2-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.1.2-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.1.2-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.1.2-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-manual-4.1.2-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.1.2-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.1.2-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.1.2-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1018", value:TRUE);
 set_kb_item(name:"CVE-2004-1019", value:TRUE);
}

set_kb_item(name:"RHSA-2005-031", value:TRUE);
