#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16109);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1138");

 name["english"] = "RHSA-2005-010: vim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated vim packages that fix a modeline vulnerability are now available.

  VIM (Vi IMproved) is an updated and improved version of the vi screen-based
  editor.

  Ciaran McCreesh discovered a modeline vulnerability in VIM. It is possible
  that a malicious user could create a file containing a specially crafted
  modeline which could cause arbitrary command execution when viewed by a
  victim. Please note that this issue only affects users who have modelines
  and filetype plugins enabled, which is not the default. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2004-1138
  to this issue.

  All users of VIM are advised to upgrade to these erratum packages,
  which contain a backported patch for this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-010.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vim packages";
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
if ( rpm_check( reference:"vim-X11-6.0-7.19", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.0-7.19", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.0-7.19", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.0-7.19", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-X11-6.3.046-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.3.046-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.3.046-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.3.046-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"vim-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1138", value:TRUE);
}
if ( rpm_exists(rpm:"vim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1138", value:TRUE);
}

set_kb_item(name:"RHSA-2005-010", value:TRUE);
