#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12497);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0426");

 name["english"] = "RHSA-2004-192: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated rsync package that fixes a directory traversal security flaw is
  now available.

  Rsync is a program for synchronizing files over a network.

  Rsync before 2.6.1 does not properly sanitize paths when running a
  read/write daemon without using chroot. This could allow a remote attacker
  to write files outside of the module\'s "path", depending on the privileges
  assigned to the rsync daemon. Users not running an rsync daemon, running a
  read-only daemon, or running a chrooted daemon are not affected by this
  issue. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2004-0426 to this issue.

  Users of Rsync are advised to upgrade to this updated package, which
  contains a backported patch and is not affected by this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-192.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rsync packages";
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
if ( rpm_check( reference:"rsync-2.5.7-3.21AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-4.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"rsync-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0426", value:TRUE);
}
if ( rpm_exists(rpm:"rsync-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0426", value:TRUE);
}

set_kb_item(name:"RHSA-2004-192", value:TRUE);
