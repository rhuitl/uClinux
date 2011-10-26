#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16108);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2002-0875");

 name["english"] = "RHSA-2005-005: fam";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated fam packages that fix an information disclosure bug are now
  available.

  FAM, the File Alteration Monitor, provides a daemon and an API which
  applications can use for notification of changes in specific files or
  directories.

  A bug has been found in the way FAM handles group permissions. It is
  possible that a local unprivileged user can use a flaw in FAM\'s group
  handling to discover the names of files which are only viewable to users in
  the \'root\' group. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2002-0875 to this issue. This
  issue only affects the version of FAM shipped with Red Hat Enterprise Linux
  2.1.

  Users of FAM should update to these updated packages which contain
  backported patches and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-005.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fam packages";
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
if ( rpm_check( reference:"fam-2.6.4-12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fam-devel-2.6.4-12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"fam-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0875", value:TRUE);
}

set_kb_item(name:"RHSA-2005-005", value:TRUE);
