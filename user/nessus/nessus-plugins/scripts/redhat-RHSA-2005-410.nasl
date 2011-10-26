#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18470);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0372");

 name["english"] = "RHSA-2005-410: gftp";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gFTP package that fixes a directory traversal issue is now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  gFTP is a multi-threaded FTP client for the X Window System.

  A directory traversal bug was found in gFTP. If a user can be tricked into
  downloading a file from a malicious ftp server, it is possible to overwrite
  arbitrary files owned by the victim. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0372 to
  this issue.

  Users of gftp should upgrade to this updated package, which contains a
  backported fix for this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-410.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gftp packages";
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
if ( rpm_check( reference:"gftp-2.0.8-5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gftp-2.0.14-4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gftp-2.0.17-5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gftp-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0372", value:TRUE);
}
if ( rpm_exists(rpm:"gftp-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0372", value:TRUE);
}
if ( rpm_exists(rpm:"gftp-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0372", value:TRUE);
}

set_kb_item(name:"RHSA-2005-410", value:TRUE);
