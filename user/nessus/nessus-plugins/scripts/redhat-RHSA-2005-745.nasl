#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19489);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2368");

 name["english"] = "RHSA-2005-745: vim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated vim packages that fix a security issue are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  VIM (VIsual editor iMproved) is a version of the vi editor.

  A bug was found in the way VIM processes modelines. If a user with
  modelines enabled opens a text file with a carefully crafted modeline,
  arbitrary commands may be executed as the user running VIM. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2005-2368
  to this issue.

  Users of VIM are advised to upgrade to these updated packages, which
  resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-745.html
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
if ( rpm_check( reference:"vim-X11-6.0-7.22", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.0-7.22", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.0-7.22", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.0-7.22", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-X11-6.3.046-0.30E.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.3.046-0.30E.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.3.046-0.30E.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.3.046-0.30E.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-X11-6.3.046-0.40E.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.3.046-0.40E.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.3.046-0.40E.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.3.046-0.40E.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"vim-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2368", value:TRUE);
}
if ( rpm_exists(rpm:"vim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2368", value:TRUE);
}
if ( rpm_exists(rpm:"vim-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2368", value:TRUE);
}

set_kb_item(name:"RHSA-2005-745", value:TRUE);
