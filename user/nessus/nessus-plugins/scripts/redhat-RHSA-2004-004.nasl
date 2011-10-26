#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12446);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0977", "CVE-2002-0844");

 name["english"] = "RHSA-2004-004: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated cvs packages closing a vulnerability that could allow cvs to
  attempt to create files and directories in the root file system are now
  available.

  CVS is a version control system frequently used to manage source code
  repositories.

  A flaw was found in versions of CVS prior to 1.11.10 where a malformed
  module request could cause the CVS server to attempt to create files or
  directories at the root level of the file system. However, normal file
  system permissions would prevent the creation of these misplaced
  directories. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-0977 to this issue.

  Users of CVS are advised to upgrade to these erratum packages, which
  contain a patch correcting this issue.

  For Red Hat Enterprise Linux 2.1, these updates also fix an off-by-one
  overflow in the CVS PreservePermissions code. The PreservePermissions
  feature is not used by default (and can only be used for local CVS). The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2002-0844 to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-004.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs packages";
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
if ( rpm_check( reference:"cvs-1.11.1p1-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.2-14", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cvs-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0977", value:TRUE);
 set_kb_item(name:"CVE-2002-0844", value:TRUE);
}
if ( rpm_exists(rpm:"cvs-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0977", value:TRUE);
 set_kb_item(name:"CVE-2002-0844", value:TRUE);
}

set_kb_item(name:"RHSA-2004-004", value:TRUE);
