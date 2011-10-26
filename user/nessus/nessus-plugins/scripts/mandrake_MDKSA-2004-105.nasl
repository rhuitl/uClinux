#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:105
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15434);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2004:105: xine-lib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:105 (xine-lib).


A number of string overflows were discovered in the xine-lib program, some of
which can be used for remote buffer overflow exploits that lead to the execution
of arbitrary code with the permissions of the user running a xine-lib-based
media application. xine-lib versions 1-rc2 through, and including, 1-rc5 are
vulnerable to these problems.
As well, a heap overflow was found in the DVD subpicture decoder of xine-lib;
this vulnerability is also remotely exploitable. All versions of xine-lib prior
to and including 0.5.2 through, and including, 1-rc5 are vulnerable to this
problem.
Patches from the xine-lib team have been backported and applied to the program
to solve these problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:105
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xine-lib package";
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
if ( rpm_check( reference:"libxine1-1-0.rc3.6.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxine1-devel-1-0.rc3.6.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-aa-1-0.rc3.6.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-arts-1-0.rc3.6.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-dxr3-1-0.rc3.6.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-esd-1-0.rc3.6.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-flac-1-0.rc3.6.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-gnomevfs-1-0.rc3.6.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-plugins-1-0.rc3.6.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
