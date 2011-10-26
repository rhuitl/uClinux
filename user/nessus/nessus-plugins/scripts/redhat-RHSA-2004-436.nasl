#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14623);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0792");

 name["english"] = "RHSA-2004-436: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated rsync package that fixes a path sanitizing bug is now available.

  The rsync program synchronizes files over a network.

  Versions of rsync up to and including version 2.6.2 contain a path
  sanitization issue. This issue could allow an attacker to read or write
  files outside of the rsync directory. This vulnerability is only
  exploitable when an rsync server is enabled and is not running within a
  chroot. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2004-0792 to this issue.

  Users of rsync are advised to upgrade to this updated package, which
  contains a backported patch and is not affected by this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-436.html
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
if ( rpm_check( reference:"rsync-2.5.7-3.21AS.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-5.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"rsync-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0792", value:TRUE);
}
if ( rpm_exists(rpm:"rsync-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0792", value:TRUE);
}

set_kb_item(name:"RHSA-2004-436", value:TRUE);
