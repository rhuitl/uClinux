#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18326);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0891");
 
 name["english"] = "Fedora Core 2 2005-267: gtk2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-267 (gtk2).

GTK+ is a multi-platform toolkit for creating graphical user
interfaces. Offering a complete set of widgets, GTK+ is suitable for
projects ranging from small one-off tools to complete application
suites.

Update Information:
David Costanzo found a bug in the way GTK+ processes BMP images.
It is possible that a specially crafted BMP image could cause a denial
of service attack in applications linked against GTK+.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0891 to this issue.



Solution : http://www.fedoranews.org/blog/index.php?p=554
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gtk2 package";
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
if ( rpm_check( reference:"gtk2-2.4.14-2.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.4.14-2.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-debuginfo-2.4.14-2.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gtk2-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0891", value:TRUE);
}
