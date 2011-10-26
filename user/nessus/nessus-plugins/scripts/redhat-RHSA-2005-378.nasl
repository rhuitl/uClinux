#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19283);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1111");

 name["english"] = "RHSA-2005-378: cpio";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated cpio package that fixes multiple issues is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GNU cpio copies files into or out of a cpio or tar archive.

  A race condition bug was found in cpio. It is possible for a local
  malicious user to modify the permissions of a local file if they have write
  access to a directory in which a cpio archive is being extracted. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-1111 to this issue.

  Additionally, this update adds cpio support for archives larger than 2GB.
  However, the size of individual files within an archive is limited to 4GB.

  All users of cpio are advised to upgrade to this updated package, which
  contains backported fixes for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-378.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cpio packages";
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
if ( rpm_check( reference:"cpio-2.5-4.RHEL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cpio-2.5-8.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cpio-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1111", value:TRUE);
}
if ( rpm_exists(rpm:"cpio-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1111", value:TRUE);
}

set_kb_item(name:"RHSA-2005-378", value:TRUE);
