#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19490);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2499");

 name["english"] = "RHSA-2005-747: slocate";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated slocate package that fixes a denial of service issue is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Slocate is a security-enhanced version of locate. Like locate, slocate
  searches through a nightly-updated central database for files that match a
  given pattern.

  A bug was found in the way slocate processes very long paths. A local user
  could create a carefully crafted directory structure that would prevent
  updatedb from completing its file system scan, resulting in an incomplete
  slocate database. The Common Vulnerabilities and Exposures project has
  assigned the name CVE-2005-2499 to this issue.

  Users are advised to upgrade to this updated package, which includes a
  backported patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-747.html
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
if ( rpm_check( reference:"slocate-2.7-1.el2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"slocate-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2499", value:TRUE);
}

set_kb_item(name:"RHSA-2005-747", value:TRUE);
