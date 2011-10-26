#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18469);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0758", "CVE-2005-0988", "CVE-2005-1228");

 name["english"] = "RHSA-2005-357: gzip";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gzip package is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The gzip package contains the GNU gzip data compression program.

  A bug was found in the way zgrep processes file names. If a user can be
  tricked into running zgrep on a file with a carefully crafted file name,
  arbitrary commands could be executed as the user running zgrep. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0758 to this issue.

  A bug was found in the way gunzip modifies permissions of files being
  decompressed. A local attacker with write permissions in the directory in
  which a victim is decompressing a file could remove the file being written
  and replace it with a hard link to a different file owned by the victim.
  gunzip then gives the linked file the permissions of the uncompressed file.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0988 to this issue.

  A directory traversal bug was found in the way gunzip processes the -N
  flag. If a victim decompresses a file with the -N flag, gunzip fails to
  sanitize the path which could result in a file owned by the victim being
  overwritten. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-1228 to this issue.

  Users of gzip should upgrade to this updated package, which contains
  backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-357.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gzip packages";
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
if ( rpm_check( reference:"gzip-1.3-18.rhel2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.3.3-12.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.3.3-15.rhel4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gzip-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0758", value:TRUE);
 set_kb_item(name:"CVE-2005-0988", value:TRUE);
 set_kb_item(name:"CVE-2005-1228", value:TRUE);
}
if ( rpm_exists(rpm:"gzip-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0758", value:TRUE);
 set_kb_item(name:"CVE-2005-0988", value:TRUE);
 set_kb_item(name:"CVE-2005-1228", value:TRUE);
}
if ( rpm_exists(rpm:"gzip-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0758", value:TRUE);
 set_kb_item(name:"CVE-2005-0988", value:TRUE);
 set_kb_item(name:"CVE-2005-1228", value:TRUE);
}

set_kb_item(name:"RHSA-2005-357", value:TRUE);
