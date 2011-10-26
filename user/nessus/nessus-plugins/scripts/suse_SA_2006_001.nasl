#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:001
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20483);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:001: xpdf,kpdf,gpdf,kword";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:001 (xpdf,kpdf,gpdf,kword).


'infamous41md', Chris Evans and Dirk Mueller discovered multiple
places in xpdf code where integer variables are insufficiently
checked for range or overflow. Specially crafted PDF files could
lead to executing arbitrary code.

Copies of xpdf code are also contained in cups, kpdf, kword, gpdf,
libextractor, pdf2html, poppler and tetex. Updates for those are in
the works.


Solution : http://www.suse.de/security/advisories/2006_01_xpdf.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf,kpdf,gpdf,kword package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gpdf-2.10.0-12.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-pdf-3.4.2-12.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-wordprocessing-1.4.1-10.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"poppler-0.4.2-3.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"poppler-devel-0.4.2-3.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.00-92.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-wordprocessing-1.2.92-89", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-2.02pl1-150", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpdf-0.112.1-26.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-pdf-3.2.1-67.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-wordprocessing-1.3-67.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.00-64.35", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpdf-0.131-11.10", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-pdf-3.3.0-13.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-wordprocessing-1.3.3-3.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.00-78.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpdf-2.10.0-4.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-pdf-3.4.0-11.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-wordprocessing-1.3.5-11.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.00-87.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
