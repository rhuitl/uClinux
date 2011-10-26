#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20231);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-3186", "CVE-2005-2975", "CVE-2005-3186");
 
 name["english"] = "Fedora Core 3 2005-1087: gtk2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1087 (gtk2).

GTK+ is a multi-platform toolkit for creating graphical user
interfaces. Offering a complete set of widgets, GTK+ is suitable for
projects ranging from small one-off tools to complete application
suites.

Update Information:

The gtk2 package contains the GIMP ToolKit (GTK+), a library
for creating graphical user interfaces for the X Window System.

A bug was found in the way gtk2 processes XPM images. An
attacker could create a carefully crafted XPM file in such a
way that it could cause an application linked with gtk2 to
execute arbitrary code when the file was opened by a victim.
The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-3186 to this issue.

Ludwig Nussel discovered an infinite-loop denial of service
bug in the way gtk2 processes XPM images. An attacker could
create a carefully crafted XPM file in such a way that it
could cause an application linked with gtk2 to stop
responding when the file was opened by a victim. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-2975 to this issue.

Users of gtk2 are advised to upgrade to these updated
packages, which contain backported patches and are not
vulnerable to these issues.


Solution : Get the newest Fedora Updates
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
if ( rpm_check( reference:"gtk2-2.4.14-4.fc3.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.4.14-4.fc3.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gtk2-", release:"FC3") )
{
 set_kb_item(name:"CAN-2005-3186", value:TRUE);
 set_kb_item(name:"CVE-2005-2975", value:TRUE);
 set_kb_item(name:"CVE-2005-3186", value:TRUE);
}
