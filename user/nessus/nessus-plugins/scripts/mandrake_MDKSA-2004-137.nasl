#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:137-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15793);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2004:137-1: libxpm4";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:137-1 (libxpm4).



The XPM library which is part of the XFree86/XOrg project is used by several
GUI applications to process XPM image files.

A source code review of the XPM library, done by Thomas Biege of the SuSE
Security-Team revealed several different kinds of bugs. These bugs include
integer overflows, out-of-bounds memory access, shell command execution, path
traversal, and endless loops.

These bugs can be exploited by remote and/or local attackers to gain access to
the system or to escalate their local privileges, by using a specially crafted
xpm image.

Update:

The previous libxpm4 update had a linking error that resulted in a missing
s_popen symbol error running applications dependant on the library. In
addition, the file path checking in the security updates prevented some
applications, like gimp-2.0 from being able to save xpm format images.

Updated packages are patched to correct all these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:137-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libxpm4 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libxpm4-3.4k-27.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-28.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-28.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-27.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
