#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21916);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");

 name["english"] = "RHSA-2006-0573: openoffice.org";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openoffice.org packages are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  OpenOffice.org is an office productivity suite that includes desktop
  applications such as a word processor, spreadsheet, presentation manager,
  formula editor, and drawing program.

  A Sun security specialist reported an issue with the application framework.
  An attacker could put macros into document locations that could cause
  OpenOffice.org to execute them when the file was opened by a victim.
  (CVE-2006-2198)

  A bug was found in the OpenOffice.org Java virtual machine implementation.
  An attacker could write a carefully crafted Java applet that can break
  through the "sandbox" and have full access to system resources with the
  current user privileges. (CVE-2006-2199)

  A buffer overflow bug was found in the OpenOffice.org file processor. An
  attacker could create a carefully crafted XML file that could cause
  OpenOffice.org to write data to an arbitrary location in memory when the
  file was opened by a victim. (CVE-2006-3117)

  All users of OpenOffice.org are advised to upgrade to these updated
  packages, which contain backported fixes for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0573.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openoffice.org packages";
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
if ( rpm_check( reference:"openoffice.org-1.1.2-34.2.0.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.2-34.2.0.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.2-34.2.0.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-1.1.2-34.6.0.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.2-34.6.0.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-kde-1.1.2-34.6.0.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.2-34.6.0.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openoffice.org-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-2198", value:TRUE);
 set_kb_item(name:"CVE-2006-2199", value:TRUE);
 set_kb_item(name:"CVE-2006-3117", value:TRUE);
}
if ( rpm_exists(rpm:"openoffice.org-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-2198", value:TRUE);
 set_kb_item(name:"CVE-2006-2199", value:TRUE);
 set_kb_item(name:"CVE-2006-3117", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0573", value:TRUE);
