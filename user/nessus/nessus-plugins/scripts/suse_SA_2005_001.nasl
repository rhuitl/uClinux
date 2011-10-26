#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:001
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16305);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1183", "CVE-2004-1308");
 
 name["english"] = "SUSE-SA:2005:001: libtiff/tiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:001 (libtiff/tiff).


Libtiff supports reading, writing, and manipulating of TIFF image files.
iDEFENSE reported an integer overflow in libtiff that can be exploited by
specific TIFF images to trigger a heap-based buffer overflow afterwards.

This bug can be used by external attackers to execute arbitrary code
over the network by placing special image files on web-pages and
alike.

Additionally a buffer overflow in tiffdump was fixed.



Solution : http://www.suse.de/security/advisories/2005_01_libtiff_tiff.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff/tiff package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libtiff-3.5.7-379", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tiff-3.5.7-379", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-379", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tiff-3.5.7-379", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-379", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tiff-3.5.7-379", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.6.1-38.14", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tiff-3.6.1-38.14", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.6.1-47.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.6.1-47.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tiff-3.6.1-47.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"SUSE8.1")
 || rpm_exists(rpm:"libtiff-", release:"SUSE8.2")
 || rpm_exists(rpm:"libtiff-", release:"SUSE9.0")
 || rpm_exists(rpm:"libtiff-", release:"SUSE9.1")
 || rpm_exists(rpm:"libtiff-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2004-1183", value:TRUE);
 set_kb_item(name:"CVE-2004-1308", value:TRUE);
}
