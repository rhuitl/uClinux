#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:086
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13899);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:086: tetex";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:086 (tetex).


A problem was discovered in the temporary file handling capabilities of some
teTeX filters by zen-parse. These filters are used as print filters
automatically when printing .dvi files using lpr. This can lead to elevated
privileges. This update relies on the updated mktemp packages for 7.x in
MDKA-2001:021, which gives mktemp the ability to create temporary directories.
8.x users already have a mktemp that works in this fashion.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:086
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tetex package";
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
if ( rpm_check( reference:"tetex-1.0.7-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-1.0.7-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-1.0.7-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-1.0.7-11.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-11.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-1.0.7-11.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-1.0.7-11.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-11.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-11.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-11.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-1.0.7-21.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-21.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-1.0.7-21.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-1.0.7-21.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvipdfm-1.0.7-21.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-21.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-21.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-21.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-1.0.7-31.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-31.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-1.0.7-31.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-1.0.7-31.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvipdfm-1.0.7-31.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-31.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-31.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-31.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
