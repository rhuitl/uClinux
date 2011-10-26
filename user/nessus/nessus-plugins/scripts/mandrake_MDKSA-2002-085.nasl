#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:085
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13983);
 script_bugtraq_id(6119);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1277");
 
 name["english"] = "MDKSA-2002:085: WindowMaker";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:085 (WindowMaker).


Al Viro discovered a vulnerability in the WindowMaker window manager. A function
used to load images, for example when configuring a new background image or
previewing themes, contains a buffer overflow. The function calculates the
amount of memory necessary to load the image by doing some multiplication but
does not check the results of this multiplication, which may not fit into the
destination variable, resulting in a buffer overflow when the image is loaded.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:085
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the WindowMaker package";
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
if ( rpm_check( reference:"WindowMaker-0.62.1-18.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-devel-0.62.1-18.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-0.64.0-8.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-devel-0.64.0-8.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-0.64.0-8.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-devel-0.64.0-8.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-0.65.1-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-devel-0.65.1-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-0.65.1-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-devel-0.65.1-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-0.80.0-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-devel-0.80.0-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-0.80.0-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-devel-0.80.0-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-0.80.1-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-devel-0.80.1-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-0.80.1-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-devel-0.80.1-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"WindowMaker-", release:"MDK7.2")
 || rpm_exists(rpm:"WindowMaker-", release:"MDK8.0")
 || rpm_exists(rpm:"WindowMaker-", release:"MDK8.1")
 || rpm_exists(rpm:"WindowMaker-", release:"MDK8.2")
 || rpm_exists(rpm:"WindowMaker-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1277", value:TRUE);
}
