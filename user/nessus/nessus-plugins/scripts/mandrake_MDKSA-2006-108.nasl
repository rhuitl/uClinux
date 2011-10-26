#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:108
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21752);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1502", "CVE-2006-2802");
 
 name["english"] = "MDKSA-2006:108: xine-lib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:108 (xine-lib).



A buffer overflow in the HTTP Plugin (xineplug_inp_http.so) for xine-lib

1.1.1 allows remote attackers to cause a denial of service (application

crash) via a long reply from an HTTP server, as demonstrated using gxine

0.5.6. (CVE-2006-2802)



In addition, a possible buffer overflow exists in the AVI demuxer,

similar in nature to CVE-2006-1502 for MPlayer. The Corporate 3 release

of xine-lib does not have this issue.



The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:108
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xine-lib package";
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
if ( rpm_check( reference:"libxine1-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxine1-devel-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-aa-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-arts-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-dxr3-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-esd-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-flac-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-gnomevfs-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-plugins-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-polyp-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-smb-1.0-8.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxine1-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxine1-devel-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-aa-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-arts-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-dxr3-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-esd-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-flac-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-gnomevfs-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-image-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-plugins-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-polyp-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-smb-1.1.0-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xine-lib-", release:"MDK10.2")
 || rpm_exists(rpm:"xine-lib-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1502", value:TRUE);
 set_kb_item(name:"CVE-2006-2802", value:TRUE);
}
