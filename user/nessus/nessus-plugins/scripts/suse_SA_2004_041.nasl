#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:041
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15755);
 script_bugtraq_id(11694);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2004:041: xshared, XFree86-libs, xorg-x11-libs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:041 (xshared, XFree86-libs, xorg-x11-libs).


The XPM library which is part of the XFree86/XOrg project is used by
several GUI applications to process XPM image files.
A source code review done by Thomas Biege of the SuSE Security-Team
revealed several different kinds of bugs.
The bug types are:
- integer overflows
- out-of-bounds memory access
- shell command execution
- path traversal
- endless loops
By providing a special image these bugs can be exploited by remote and/or
local attackers to gain access to the system or to escalate their local
privileges.



Solution : http://www.suse.de/security/2004_41_xshared_XFree86_libs_xorg_x11_libs.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xshared, XFree86-libs, xorg-x11-libs package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"xshared-4.2.0-269", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0-132", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0.1-57", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.99.902-43.35.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-libs-6.8.1-15.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
