#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:081-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21356);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1526");
 
 name["english"] = "MDKSA-2006:081-1: xorg-x11";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:081-1 (xorg-x11).



A problem was discovered in xorg-x11 where the X render extension would

mis-calculate the size of a buffer, leading to an overflow that could

possibly be exploited by clients of the X server.



Update:



Rafael Bermudez noticed that the patch for 2006 was mis-applied. This

update resolves that issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:081-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xorg-x11 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libxorg-x11-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxorg-x11-devel-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxorg-x11-static-devel-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-100dpi-fonts-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-75dpi-fonts-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-cyrillic-fonts-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-doc-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-glide-module-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xauth-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xdmx-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xfs-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xnest-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xprt-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xvfb-6.9.0-5.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xorg-x11-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1526", value:TRUE);
}
