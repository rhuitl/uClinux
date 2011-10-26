#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22223);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3813");

 name["english"] = "RHSA-2006-0605: perl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Perl packages that fix security a security issue are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Perl is a high-level programming language commonly used for system
  administration utilities and Web programming.

  Kevin Finisterre discovered a flaw in sperl, the Perl setuid wrapper, which
  can cause debugging information to be logged to arbitrary files. By setting
  an environment variable, a local user could cause sperl to create, as root,
  files with arbitrary filenames, or append the debugging information to
  existing files. (CVE-2005-0155)

  A fix for this issue was first included in the update RHSA-2005:103
  released in February 2005. However the patch to correct this issue was
  dropped from the update RHSA-2005:674 made in October 2005. This
  regression has been assigned CVE-2006-3813.

  Users of Perl are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0605.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"perl-5.8.5-36.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-suidperl-5.8.5-36.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"perl-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3813", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0605", value:TRUE);
