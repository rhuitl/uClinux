#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17980);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0891");

 name["english"] = "RHSA-2005-343: gdk";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gdk-pixbuf packages that fix a double free vulnerability are now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The gdk-pixbuf package contains an image loading library used with the
  GNOME GUI desktop environment.

  A bug was found in the way gdk-pixbuf processes BMP images. It is possible
  that a specially crafted BMP image could cause a denial of service attack
  on applications linked against gdk-pixbuf. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0891 to
  this issue.

  Users of gdk-pixbuf are advised to upgrade to these packages, which contain
  a backported patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-343.html
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
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-12.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-12.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.22.0-12.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-12.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-12.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.22.0-12.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-16.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-16.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gdk-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0891", value:TRUE);
}
if ( rpm_exists(rpm:"gdk-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0891", value:TRUE);
}
if ( rpm_exists(rpm:"gdk-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0891", value:TRUE);
}

set_kb_item(name:"RHSA-2005-343", value:TRUE);
