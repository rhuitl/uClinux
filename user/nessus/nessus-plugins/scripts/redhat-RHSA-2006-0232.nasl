#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21005);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0300");

 name["english"] = "RHSA-2006-0232: tar";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated tar package that fixes a buffer overflow bug is now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having Moderate security impact by the Red
  Hat Security Response Team.

  The GNU tar program saves many files together in one archive and can
  restore individual files (or all of the files) from that archive.

  Jim Meyering discovered a buffer overflow bug in the way GNU tar extracts
  malformed archives. By tricking a user into extracting a malicious tar
  archive, it is possible to execute arbitrary code as the user running tar.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) assigned
  the name CVE-2006-0300 to this issue.

  Users of tar should upgrade to this updated package, which contains a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0232.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tar packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"tar-1.14-9.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"tar-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0300", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0232", value:TRUE);
