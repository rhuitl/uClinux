#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20237);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");

 name["english"] = "RHSA-2005-810: gdk";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gdk-pixbuf packages that fix several security issues are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The gdk-pixbuf package contains an image loading library used with the
  GNOME GUI desktop environment.

  A bug was found in the way gdk-pixbuf processes XPM images. An attacker
  could create a carefully crafted XPM file in such a way that it could cause
  an application linked with gdk-pixbuf to execute arbitrary code when the
  file was opened by a victim. The Common Vulnerabilities and Exposures
  project has assigned the name CVE-2005-3186 to this issue.

  Ludwig Nussel discovered an integer overflow bug in the way gdk-pixbuf
  processes XPM images. An attacker could create a carefully crafted XPM file
  in such a way that it could cause an application linked with gdk-pixbuf to
  execute arbitrary code or crash when the file was opened by a victim. The
  Common Vulnerabilities and Exposures project has assigned the name
  CVE-2005-2976 to this issue.

  Ludwig Nussel also discovered an infinite-loop denial of service bug in the
  way gdk-pixbuf processes XPM images. An attacker could create a carefully
  crafted XPM file in such a way that it could cause an application linked
  with gdk-pixbuf to stop responding when the file was opened by a victim.
  The Common Vulnerabilities and Exposures project has assigned the name
  CVE-2005-2975 to this issue.

  Users of gdk-pixbuf are advised to upgrade to these updated packages, which
  contain backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-810.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdk packages";
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
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-12.el2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-12.el2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.22.0-12.el2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-13.el3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-13.el3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.22.0-13.el3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-17.el4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-17.el4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gdk-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2975", value:TRUE);
 set_kb_item(name:"CVE-2005-2976", value:TRUE);
 set_kb_item(name:"CVE-2005-3186", value:TRUE);
}
if ( rpm_exists(rpm:"gdk-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2975", value:TRUE);
 set_kb_item(name:"CVE-2005-2976", value:TRUE);
 set_kb_item(name:"CVE-2005-3186", value:TRUE);
}
if ( rpm_exists(rpm:"gdk-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2975", value:TRUE);
 set_kb_item(name:"CVE-2005-2976", value:TRUE);
 set_kb_item(name:"CVE-2005-3186", value:TRUE);
}

set_kb_item(name:"RHSA-2005-810", value:TRUE);
