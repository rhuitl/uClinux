#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20367);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2004-0976", "CVE-2005-0448", "CVE-2005-3962");

 name["english"] = "RHSA-2005-881: perl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Perl packages that fix security issues and bugs are now available
  for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Perl is a high-level programming language commonly used for system
  administration utilities and Web programming.

  An integer overflow bug was found in Perl\'s format string processor. It is
  possible for an attacker to cause perl to crash or execute arbitrary code
  if the attacker is able to process a malicious format string. This issue
  is only exploitable through a script wich passes arbitrary untrusted
  strings to the format string processor. The Common Vulnerabilities and
  Exposures project assigned the name CVE-2005-3962 to this issue.

  Paul Szabo discovered a bug in the way Perl\'s File::Path::rmtree module
  removed directory trees. If a local user has write permissions to a
  subdirectory within the tree being removed by File::Path::rmtree, it is
  possible for them to create setuid binary files. (CVE-2005-0448)

  Solar Designer discovered several temporary file bugs in various Perl
  modules. A local attacker could overwrite or create files as the user
  running a Perl script that uses a vulnerable module. (CVE-2004-0976)

  Users of Perl are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues as well as fixes for
  several bugs.




Solution : http://rhn.redhat.com/errata/RHSA-2005-881.html
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
if ( rpm_check( reference:"perl-5.8.0-90.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-CGI-2.89-90.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-CPAN-1.61-90.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DB_File-1.806-90.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-suidperl-5.8.0-90.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"perl-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0976", value:TRUE);
 set_kb_item(name:"CVE-2005-0448", value:TRUE);
 set_kb_item(name:"CVE-2005-3962", value:TRUE);
}

set_kb_item(name:"RHSA-2005-881", value:TRUE);
