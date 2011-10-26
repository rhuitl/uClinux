#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14326);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");

 name["english"] = "RHSA-2004-414: qt";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated qt packages that fix security issues in several of the image
  decoders are now available.

  Qt is a software toolkit that simplifies the task of writing and
  maintaining GUI (Graphical User Interface) applications for the X Window
  System.

  During a security audit, Chris Evans discovered a heap overflow in the BMP
  image decoder in Qt versions prior to 3.3.3. An attacker could create a
  carefully crafted BMP file in such a way that it would cause an application
  linked with Qt to crash or possibly execute arbitrary code when the file
  was opened by a victim. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0691 to this issue.

  Additionally, various flaws were discovered in the GIF, XPM, and JPEG
  decoders in Qt versions prior to 3.3.3. An attacker could create carefully
  crafted image files in such a way that it could cause an application linked
  against Qt to crash when the file was opened by a victim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  names CVE-2004-0692 and CVE-2004-0693 to these issues.

  Users of Qt should update to these updated packages which contain
  backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-414.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the qt packages";
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
if ( rpm_check( reference:"qt-2.3.1-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-designer-2.3.1-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-devel-2.3.1-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-static-2.3.1-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-Xt-2.3.1-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-3.1.2-13.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-config-3.1.2-13.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-designer-3.1.2-13.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-devel-3.1.2-13.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-MySQL-3.1.2-13.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"qt-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0691", value:TRUE);
 set_kb_item(name:"CVE-2004-0692", value:TRUE);
 set_kb_item(name:"CVE-2004-0693", value:TRUE);
}
if ( rpm_exists(rpm:"qt-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0691", value:TRUE);
 set_kb_item(name:"CVE-2004-0692", value:TRUE);
 set_kb_item(name:"CVE-2004-0693", value:TRUE);
}

set_kb_item(name:"RHSA-2004-414", value:TRUE);
