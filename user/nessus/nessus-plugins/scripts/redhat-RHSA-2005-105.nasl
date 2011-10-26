#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16361);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0155", "CVE-2005-0156");

 name["english"] = "RHSA-2005-105: perl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Perl packages that fix several security issues are now available
  for Red Hat Enterprise Linux 3.

  Perl is a high-level programming language commonly used for system
  administration utilities and Web programming.

  Kevin Finisterre discovered a stack based buffer overflow flaw in sperl,
  the Perl setuid wrapper. A local user could create a sperl executable
  script with a carefully created path name, overflowing the buffer and
  leading to root privilege escalation. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0156 to
  this issue.

  Kevin Finisterre discovered a flaw in sperl which can cause debugging
  information to be logged to arbitrary files. By setting an environment
  variable, a local user could cause sperl to create, as root, files with
  arbitrary filenames, or append the debugging information to existing files.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0155 to this issue.

  Users of Perl are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-105.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl packages";
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
if ( rpm_check( reference:"perl-5.8.0-89.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-CGI-2.81-89.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-CPAN-1.61-89.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DB_File-1.804-89.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-suidperl-5.8.0-89.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"perl-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0155", value:TRUE);
 set_kb_item(name:"CVE-2005-0156", value:TRUE);
}

set_kb_item(name:"RHSA-2005-105", value:TRUE);
