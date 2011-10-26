#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17170);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1138", "CVE-2005-0069");

 name["english"] = "RHSA-2005-036: vim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated vim packages that fix security vulnerabilities are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  VIM (Vi IMproved) is an updated and improved version of the vi screen-based
  editor.

  Ciaran McCreesh discovered a modeline vulnerability in VIM. An attacker
  could create a text file containing a specially crafted modeline which
  could cause arbitrary command execution when viewed by a victim using VIM.
  The Common Vulnerabilities and Exposures project has assigned the name
  CVE-2004-1138 to this issue. Please note that this issue only affects
  users who have modelines and filetype plugins enabled, which is not the
  default.

  The Debian Security Audit Project discovered an insecure temporary file
  usage in VIM. A local user could overwrite or create files as a different
  user who happens to run one of the the vulnerable utilities. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0069 to this issue.

  All users of VIM are advised to upgrade to these erratum packages,
  which contain backported patches for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-036.html
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
if ( rpm_check( reference:"vim-X11-6.3.046-0.40E.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.3.046-0.40E.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.3.046-0.40E.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.3.046-0.40E.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"vim-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1138", value:TRUE);
 set_kb_item(name:"CVE-2005-0069", value:TRUE);
}

set_kb_item(name:"RHSA-2005-036", value:TRUE);
