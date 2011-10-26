#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18160);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0968", "CVE-2004-1382", "CVE-2004-1453");

 name["english"] = "RHSA-2005-261: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated glibc packages that address several bugs are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The GNU libc packages (known as glibc) contain the standard C libraries
  used by applications.

  Flaws in the catchsegv and glibcbug scripts were discovered. A local user
  could utilize these flaws to overwrite files via a symlink attack on
  temporary files. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0968 and CVE-2004-1382 to
  these issues.

  It was discovered that the use of LD_DEBUG and LD_SHOW_AUXV were not
  restricted for a setuid program. A local user could utilize this flaw to
  gain information, such as the list of symbols used by the program. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-1453 to this issue.

  This erratum also addresses the following bugs in the GNU C Library:
  - Now avoids calling sigaction (SIGPIPE, ...) in syslog implementation
  - Fixed poll on Itanium
  - Now allows setenv/putenv in shared library constructors

  Users of glibc are advised to upgrade to these erratum packages that remove
  the unecessary glibcbug script and contain backported patches to correct
  these other issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-261.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the glibc packages";
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
if ( rpm_check( reference:"glibc-2.2.4-32.20", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  glibc-2.2.4-32.20", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-common-2.2.4-32.20", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.4-32.20", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.4-32.20", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.4-32.20", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"glibc-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0968", value:TRUE);
 set_kb_item(name:"CVE-2004-1382", value:TRUE);
 set_kb_item(name:"CVE-2004-1453", value:TRUE);
}

set_kb_item(name:"RHSA-2005-261", value:TRUE);
