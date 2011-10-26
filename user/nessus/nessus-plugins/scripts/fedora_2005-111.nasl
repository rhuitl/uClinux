#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16301);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0201");
 
 name["english"] = "Fedora Core 3 2005-111: dbus";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-111 (dbus).


D-BUS is a system for sending messages between applications. It is
used both for the systemwide message bus service, and as a
per-user-login-session messaging facility.

Update Information:

Security fix for Bug#146765 (CVE-2005-0201)


Solution : http://www.fedoranews.org/blog/index.php?p=364
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dbus package";
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
if ( rpm_check( reference:"dbus-0.22-10.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dbus-devel-0.22-10.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dbus-glib-0.22-10.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dbus-x11-0.22-10.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dbus-python-0.22-10.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dbus-debuginfo-0.22-10.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"dbus-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0201", value:TRUE);
}
