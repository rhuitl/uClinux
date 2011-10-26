#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12445);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-1012", "CVE-2003-1013");

 name["english"] = "RHSA-2004-002: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix two security vulnerabilities are now
  available.

  Ethereal is a program for monitoring network traffic.

  Two security issues have been found that affect Ethereal. By exploiting
  these issues it may be possible to make Ethereal crash by injecting an
  intentionally malformed packet onto the wire or by convincing someone to
  read a malformed packet trace file. It is not known if these issues could
  allow arbitrary code execution.

  The SMB dissector in Ethereal before 0.10.0 allows remote attackers to
  cause a denial of service via a malformed SMB packet that triggers a
  segmentation fault during processing of Selected packets. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-1012 to this issue.

  The Q.931 dissector in Ethereal before 0.10.0 allows remote attackers to
  cause a denial of service (crash) via a malformed Q.931, which triggers a
  null dereference. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-1013 to this issue.

  Users of Ethereal should update to these erratum packages containing
  Ethereal version 0.10.0, which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-002.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal packages";
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
if ( rpm_check( reference:"ethereal-0.10.0a-0.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.0a-0.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.0a-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.0a-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-1012", value:TRUE);
 set_kb_item(name:"CVE-2003-1013", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-1012", value:TRUE);
 set_kb_item(name:"CVE-2003-1013", value:TRUE);
}

set_kb_item(name:"RHSA-2004-002", value:TRUE);
