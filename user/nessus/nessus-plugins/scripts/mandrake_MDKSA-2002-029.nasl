#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:029
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13936);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:029: imlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:029 (imlib).


Previous versions of imlib, prior to 1.9.13, would fall back to the NetPBM
library which is not suitable for loading untrusted images due to various
problem in it's code. The new imlib also fixes some problems with arguments
passed to malloc(). These problems could allow attackers to construct images
that could cause crashes or, potentially, the execution of arbitrary code when
said images are loaded by a viewer that uses imlib.
Thanks to Alan Cox and Al Viro for discovering the problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:029
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imlib package";
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
if ( rpm_check( reference:"imlib-1.9.13-2.5mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-2.5mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-2.5mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.13-2.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-2.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-2.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.13-2.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-2.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-1.9.13-2.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-devel-1.9.13-2.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.13-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-1.9.13-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-devel-1.9.13-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.13-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-1.9.13-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-devel-1.9.13-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
