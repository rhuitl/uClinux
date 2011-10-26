#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14738);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");

 name["english"] = "RHSA-2004-447: gdk";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gdk-pixbuf packages that fix several security flaws are now available.

  The gdk-pixbuf package contains an image loading library used with the
  GNOME GUI desktop environment.

  [Updated 15th September 2004]
  Packages have been updated to correct a bug which caused the xpm loader
  to fail.

  During testing of a previously fixed flaw in Qt (CVE-2004-0691), a flaw was
  discovered in the BMP image processor of gdk-pixbuf. An attacker could
  create a carefully crafted BMP file which would cause an application
  to enter an infinite loop and not respond to user input when the file was
  opened by a victim. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0753 to this issue.

  During a security audit, Chris Evans discovered a stack and a heap overflow
  in the XPM image decoder. An attacker could create a carefully crafted XPM
  file which could cause an application linked with gtk2 to crash or possibly
  execute arbitrary code when the file was opened by a victim.
  (CVE-2004-0782, CVE-2004-0783)

  Chris Evans also discovered an integer overflow in the ICO image decoder.
  An attacker could create a carefully crafted ICO file which could cause an
  application linked with gtk2 to crash when the file is opened by a victim.
  (CVE-2004-0788)

  These packages have also been updated to correct a bug which caused the xpm
  loader to fail.

  Users of gdk-pixbuf are advised to upgrade to these packages, which
  contain backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-447.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdk packages";
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
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-11.2.2E", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-11.2.2E", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.22.0-11.2.2E", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-11.3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-11.3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.22.0-11.3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gdk-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0753", value:TRUE);
 set_kb_item(name:"CVE-2004-0782", value:TRUE);
 set_kb_item(name:"CVE-2004-0783", value:TRUE);
 set_kb_item(name:"CVE-2004-0788", value:TRUE);
}
if ( rpm_exists(rpm:"gdk-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0753", value:TRUE);
 set_kb_item(name:"CVE-2004-0782", value:TRUE);
 set_kb_item(name:"CVE-2004-0783", value:TRUE);
 set_kb_item(name:"CVE-2004-0788", value:TRUE);
}

set_kb_item(name:"RHSA-2004-447", value:TRUE);
