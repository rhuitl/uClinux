#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19986);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2499");

 name["english"] = "RHSA-2005-346: slocate";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated slocate package that fixes a denial of service and various bugs
  is available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Slocate is a security-enhanced version of locate. Like locate, slocate
  searches through a central database (updated nightly) for files that match
  a given pattern. Slocate allows you to quickly find files anywhere on your
  system.

  A bug was found in the way slocate scans the local filesystem. A carefully
  prepared directory structure could cause updatedb\'s file system scan to
  fail silently, resulting in an incomplete slocate database. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2005-2499
  to this issue.

  Additionally this update addresses the following issues:

  - File system type exclusions were processed only when starting updatedb
  and did not reflect file systems mounted while updatedb was running
  (for example, automounted file systems.)

  - File system type exclusions were ignored for file systems that were
  mounted to a path containing a symbolic link.

  - Databases created by slocate were owned by the slocate group even if they
  were created by regular users.

  - The default configuration excluded /mnt/floppy, but not /media.

  - The default configuration did not exclude nfs4 file systems.

  Users of slocate are advised to upgrade to this updated package, which
  contains backported patches and is not affected by these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-346.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the slocate packages";
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
if ( rpm_check( reference:"slocate-2.7-13.el4.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"slocate-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2499", value:TRUE);
}

set_kb_item(name:"RHSA-2005-346", value:TRUE);
