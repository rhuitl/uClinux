#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:069
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18004);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2005-0891");
 
 name["english"] = "MDKSA-2005:069: gdk-pixbuf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:069 (gdk-pixbuf).



A bug was discovered in the way that gdk-pixbuf processes BMP images which
could allow for a specially crafted BMP to cause a Denial of Service attack on
applications linked against gdk-pixbuf.

The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:069
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdk-pixbuf package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gdk-pixbuf-loaders-0.22.0-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-gnomecanvas1-0.22.0-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-xlib2-0.22.0-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-0.22.0-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-devel-0.22.0-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-loaders-0.22.0-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-gnomecanvas1-0.22.0-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-xlib2-0.22.0-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-0.22.0-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-devel-0.22.0-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gdk-pixbuf-", release:"MDK10.0")
 || rpm_exists(rpm:"gdk-pixbuf-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0891", value:TRUE);
}
