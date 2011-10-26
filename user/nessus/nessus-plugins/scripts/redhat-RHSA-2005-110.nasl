#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17189);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0100");

 name["english"] = "RHSA-2005-110: emacs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Emacs packages that fix a string format issue are now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team

  Emacs is a powerful, customizable, self-documenting, modeless text editor.

  Max Vozeler discovered several format string vulnerabilities in the
  movemail utility of Emacs. If a user connects to a malicious POP server,
  an attacker can execute arbitrary code as the user running emacs. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-0100 to this issue.

  Users of Emacs are advised to upgrade to these updated packages, which
  contain backported patches to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-110.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the emacs packages";
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
if ( rpm_check( reference:"emacs-21.3-19.EL.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"emacs-common-21.3-19.EL.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"emacs-el-21.3-19.EL.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"emacs-leim-21.3-19.EL.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"emacs-nox-21.3-19.EL.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"emacs-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0100", value:TRUE);
}

set_kb_item(name:"RHSA-2005-110", value:TRUE);
