#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20048);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2001-1494", "CVE-2005-2876");

 name["english"] = "RHSA-2005-782: losetup";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated util-linux and mount packages that fix two security issues are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The util-linux package contains a large variety of low-level system
  utilities that are necessary for a Linux system to function.

  The mount package contains the mount, umount, swapon and swapoff programs.

  A bug was found in the way the umount command is executed by normal users.
  It may be possible for a user to gain elevated privileges if the user is
  able to execute the "umount -r" command on a mounted file system. The
  file system will be re-mounted only with the "readonly" flag set, clearing
  flags such as "nosuid" and "noexec". The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-2876 to
  this issue.

  This update also fixes a hardlink bug in the script command for Red Hat
  Enterprise Linux 2.1. If a local user places a hardlinked file named
  "typescript" in a directory they have write access to, the file will be
  overwritten if the user running script has write permissions to the
  destination file. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2001-1494 to this issue.

  All users of util-linux and mount should upgrade to these updated packages,
  which contain backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-782.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the losetup packages";
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
if ( rpm_check( reference:"losetup-2.11g-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mount-2.11g-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.11f-20.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"losetup-2.11y-31.11", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mount-2.11y-31.11", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.11y-31.11", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.12a-16.EL4.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"losetup-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2001-1494", value:TRUE);
 set_kb_item(name:"CVE-2005-2876", value:TRUE);
}
if ( rpm_exists(rpm:"losetup-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2001-1494", value:TRUE);
 set_kb_item(name:"CVE-2005-2876", value:TRUE);
}
if ( rpm_exists(rpm:"losetup-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2001-1494", value:TRUE);
 set_kb_item(name:"CVE-2005-2876", value:TRUE);
}

set_kb_item(name:"RHSA-2005-782", value:TRUE);
