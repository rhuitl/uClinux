#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18129);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0941");

 name["english"] = "RHSA-2005-375: openoffice.org";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openoffice.org packages are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  OpenOffice.org is an office productivity suite that includes desktop
  applications such as a word processor, spreadsheet, presentation manager,
  formula editor, and drawing program.

  A heap based buffer overflow bug was found in the OpenOffice.org DOC file
  processor. An attacker could create a carefully crafted DOC file in such a
  way that it could cause OpenOffice.org to execute arbitrary code when the
  file was opened by a victim. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-0941 to this issue.

  All users of OpenOffice.org are advised to upgrade to these updated
  packages, which contain backported fixes for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-375.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openoffice.org packages";
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
if ( rpm_check( reference:"openoffice.org-1.1.2-24.2.0.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.2-24.2.0.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.2-24.2.0.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-1.1.2-24.6.0.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.2-24.6.0.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-kde-1.1.2-24.6.0.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.2-24.6.0.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openoffice.org-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0941", value:TRUE);
}
if ( rpm_exists(rpm:"openoffice.org-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0941", value:TRUE);
}

set_kb_item(name:"RHSA-2005-375", value:TRUE);
