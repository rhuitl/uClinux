#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13653);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");

 name["english"] = "RHSA-2004-392: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated php packages that fix various security issues are now available.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP server.

  Stefan Esser discovered a flaw when memory_limit is enabled in versions of
  PHP 4 before 4.3.8. If a remote attacker could force the PHP interpreter to
  allocate more memory than the memory_limit setting before script execution
  begins, then the attacker may be able to supply the contents of a PHP hash
  table remotely. This hash table could then be used to execute arbitrary
  code as the \'apache\' user. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0594 to this issue.

  This issue has a higher risk when PHP is running on an instance of Apache
  which is vulnerable to CVE-2004-0493. For Red Hat Enterprise Linux 3, this
  Apache memory exhaustion issue was fixed by a previous update,
  RHSA-2004:342. It may also be possible to exploit this issue if using a
  non-default PHP configuration with the "register_defaults" setting is
  changed to "On". Red Hat does not believe that this flaw is exploitable in
  the default configuration of Red Hat Enterprise Linux 3.

  Stefan Esser discovered a flaw in the strip_tags function in versions of
  PHP before 4.3.8. The strip_tags function is commonly used by PHP scripts
  to prevent Cross-Site-Scripting attacks by removing HTML tags from
  user-supplied form data. By embedding NUL bytes into form data, HTML tags
  can in some cases be passed intact through the strip_tags function, which
  may allow a Cross-Site-Scripting attack. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0595 to
  this issue.

  All users of PHP are advised to upgrade to these updated packages, which
  contain backported patches that address these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-392.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php packages";
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
if ( rpm_check( reference:"php-4.3.2-11.1.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.2-11.1.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.2-11.1.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.2-11.1.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.2-11.1.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.2-11.1.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0594", value:TRUE);
 set_kb_item(name:"CVE-2004-0595", value:TRUE);
}

set_kb_item(name:"RHSA-2004-392", value:TRUE);
