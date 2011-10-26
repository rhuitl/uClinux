#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19421);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2368");
 
 name["english"] = "Fedora Core 3 2005-738: vim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-738 (vim).

VIM (VIsual editor iMproved) is an updated and improved version of the
vi editor. Vi was the first real screen-based editor for UNIX, and is
still very popular. VIM improves on vi by adding new features:
multiple windows, multi-level undo, block highlighting and more.

Update Information:

CVE-2005-2368


Solution : http://www.fedoranews.org/blog/index.php?p=814
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vim package";
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
if ( rpm_check( reference:"vim-common-6.3.086-0.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.3.086-0.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.3.086-0.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-X11-6.3.086-0.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-debuginfo-6.3.086-0.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"vim-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2368", value:TRUE);
}
