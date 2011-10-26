#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19198);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2096");
 
 name["english"] = "Fedora Core 4 2005-565: rpm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-565 (rpm).

The RPM Package Manager (RPM) is a powerful command line driven
package management system capable of installing, uninstalling,
verifying, querying, and updating software packages. Each software
package consists of an archive of files along with information about
the package like its version, a description, etc.

Update Information:

This update corrects security problem CVE-2005-2096.


Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_rpm-4.4.1-22
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rpm package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"rpm-4.4.1-22", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rpm-libs-4.4.1-22", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rpm-devel-4.4.1-22", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rpm-build-4.4.1-22", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rpm-python-4.4.1-22", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"popt-1.10.1-22", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rpm-debuginfo-4.4.1-22", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"rpm-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2096", value:TRUE);
}
