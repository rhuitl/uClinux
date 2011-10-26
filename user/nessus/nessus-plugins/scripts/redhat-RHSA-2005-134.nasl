#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16369);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0100");

 name["english"] = "RHSA-2005-134: xemacs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated XEmacs packages that fix a string format issue are now available.

  XEmacs is a powerful, customizable, self-documenting, modeless text editor.

  Max Vozeler discovered several format string vulnerabilities in the
  movemail utility of XEmacs. If a user connects to a malicious POP server, an
  attacker can execute arbitrary code as the user running xemacs. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0100 to this issue.

  Users of XEmacs are advised to upgrade to these updated packages, which
  contain backported patches to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-134.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xemacs packages";
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
if ( rpm_check( reference:"xemacs-21.4.6-6.9.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xemacs-el-21.4.6-6.9.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xemacs-info-21.4.6-6.9.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xemacs-21.4.13-8.ent.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xemacs-el-21.4.13-8.ent.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xemacs-info-21.4.13-8.ent.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xemacs-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0100", value:TRUE);
}
if ( rpm_exists(rpm:"xemacs-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0100", value:TRUE);
}

set_kb_item(name:"RHSA-2005-134", value:TRUE);
