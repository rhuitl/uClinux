#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14739);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0752");

 name["english"] = "RHSA-2004-446: openoffice.org";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openoffice.org packages that fix a security issue in temporary file
  handling are now available.

  OpenOffice.org is an office productivity suite that includes desktop
  applications such as a word processor, spreadsheet, presentation manager,
  formula editor, and drawing program.

  Secunia Research reported an issue with the handling of temporary files. A
  malicious local user could use this flaw to access the contents of another
  user\'s open documents. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0752 to this issue.

  All users of OpenOffice.org are advised to upgrade to these updated
  packages which contain a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-446.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openoffice.org packages";
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
if ( rpm_check( reference:"openoffice.org-1.1.0-16.14.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.0-16.14.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.0-16.14.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openoffice.org-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0752", value:TRUE);
}

set_kb_item(name:"RHSA-2004-446", value:TRUE);
