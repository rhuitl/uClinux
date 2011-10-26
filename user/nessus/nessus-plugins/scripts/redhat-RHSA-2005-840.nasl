#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20268);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193");

 name["english"] = "RHSA-2005-840: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated xpdf package that fixes several security issues is now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The xpdf package is an X Window System-based viewer for Portable Document
  Format (PDF) files.

  Several flaws were discovered in Xpdf. An attacker could construct a
  carefully crafted PDF file that could cause Xpdf to crash or possibly
  execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project assigned the name CAN-2005-3193 to these issues.

  Users of Xpdf should upgrade to this updated package, which contains a
  backported patch to resolve these issues.

  Red Hat would like to thank Derek B. Noonburg for reporting this issue and
  providing a patch.




Solution : http://rhn.redhat.com/errata/RHSA-2005-840.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf packages";
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
if ( rpm_check( reference:"xpdf-0.92-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-2.02-9.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.00-11.9", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xpdf-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3191", value:TRUE);
 set_kb_item(name:"CVE-2005-3192", value:TRUE);
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
}
if ( rpm_exists(rpm:"xpdf-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3191", value:TRUE);
 set_kb_item(name:"CVE-2005-3192", value:TRUE);
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
}
if ( rpm_exists(rpm:"xpdf-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3191", value:TRUE);
 set_kb_item(name:"CVE-2005-3192", value:TRUE);
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
}

set_kb_item(name:"RHSA-2005-840", value:TRUE);
