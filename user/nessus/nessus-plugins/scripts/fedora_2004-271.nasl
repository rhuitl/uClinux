#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14349);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0691", "CVE-2004-0693");
 
 name["english"] = "Fedora Core 2 2004-271: qt";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-271 (qt).

Qt is a GUI software toolkit which simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications
for the X Window System.

Qt is written in C++ and is fully object-oriented.

This package contains the shared library needed to run qt
applications, as well as the README files for qt.

Update Information:

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


Solution : http://www.fedoranews.org/updates/FEDORA-2004-271.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the qt package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"qt-3.3.3-0.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-devel-3.3.3-0.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-ODBC-3.3.3-0.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-MySQL-3.3.3-0.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-PostgreSQL-3.3.3-0.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-designer-3.3.3-0.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt-debuginfo-3.3.3-0.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"qt-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0691", value:TRUE);
 set_kb_item(name:"CVE-2004-0693", value:TRUE);
}
