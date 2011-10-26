#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22265);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3467");

 name["english"] = "RHSA-2006-0634: xorg";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated X.org packages that fix a security issue are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  X.org is an open source implementation of the X Window System. It provides
  the basic low-level functionality that full-fledged graphical user
  interfaces are designed upon.

  An integer overflow flaw in the way the X.org server processes PCF files
  was discovered. A malicious authorized client could exploit this issue to
  cause a denial of service (crash) or potentially execute arbitrary code
  with root privileges on the X.org server. (CVE-2006-3467)

  Users of X.org should upgrade to these updated packages, which contain a
  backported patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0634.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xorg packages";
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
if ( rpm_check( reference:"xorg-x11-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xnest-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-devel-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-doc-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-font-utils-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-libs-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-sdk-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-tools-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-twm-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xauth-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xdm-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xfs-6.8.2-1.EL.13.37", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xorg-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3467", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0634", value:TRUE);
