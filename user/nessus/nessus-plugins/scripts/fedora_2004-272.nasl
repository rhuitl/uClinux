#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14627);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0494");
 
 name["english"] = "Fedora Core 1 2004-272: mc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-272 (mc).

Midnight Commander is a visual shell much like a file manager, only
with many more features. It is a text mode application, but it also
includes mouse support if you are running GPM. Midnight Commander's
best features are its ability to FTP, view tar and zip files, and to
poke into RPMs for specific files.

Update Information:

Security fix for http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=127973.
CVE-2004-0494 extfs vfs vulnerability in mc


Solution : http://www.fedoranews.org/updates/FEDORA-2004-272.shtml
Risk Factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mc package";
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
if ( rpm_check( reference:"mc-4.6.0-17.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mc-debuginfo-4.6.0-17.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mc-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0494", value:TRUE);
}
