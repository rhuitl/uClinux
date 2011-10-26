#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:023
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14206);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0597","CVE-2004-0598","CVE-2004-0599");
 name["english"] = "SUSE-SA:2004:023: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory 
SUSE-SA:2004:023 (libpng).


Several different security vulnerabilities were found in the PNG
library which is used by applications to support the PNG image format.

A remote attacker would be able to execute arbitrary code by triggering a
buffer overflow due to the incorrect handling of the length of
transparency chunk data and in other pathes of image processing.

A special PNG image can be used to cause an application crashing due
to NULL pointer dereference in the function png_handle_iCPP() (and
other locations). 

Integer overflows were found in png_handle_sPLT(), png_read_png()
functions and other locations. These bugs may at least crash an
application. 

Solution : http://www.suse.de/security/2004_23_libpng.html

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng package";
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
if ( rpm_check( reference:"libpng-2.1.0.12-169", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.4-115", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.5-191", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.5-191", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.5-182.7", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
